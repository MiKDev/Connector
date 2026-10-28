const fs = require('node:fs');
const fsp = fs.promises;
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Transform } = require('node:stream');
const { pipeline } = require('node:stream/promises');
const { snapshot } = require('./core.cjs');
const invoke = (sftp, method, ...args) => new Promise((resolve, reject) => sftp[method](...args, (error, value) => error ? reject(error) : resolve(value)));
function cleanPath(value, local) {
  if (typeof value !== 'string' || !value || value.length > 4096 || /[\x00-\x1f\x7f]/.test(value) || !(local ? path.isAbsolute(value) : path.posix.isAbsolute(value))) throw new Error('An absolute file path is required');
  return local ? path.resolve(value) : path.posix.normalize(value);
}
function basename(name) {
  if (typeof name !== 'string' || !name || name === '.' || name === '..' || /[\\/\x00-\x1f\x7f]/.test(name) || name.length > 255) throw new Error('Invalid file name');
  return name;
}
function kind(stat) { return stat.isSymbolicLink() ? 'link' : stat.isDirectory() ? 'folder' : stat.isFile() ? 'file' : 'special'; }
function missing(error) { return error.code === 'ENOENT' || error.code === 2; }
function quote(value) { return "'" + value.replace(/'/g, "'\\''") + "'"; }
class Files {
  constructor(store, ssh, vault, emit) {
    this.store = store; this.ssh = ssh; this.vault = vault; this.emit = emit;
    this.endpoints = new Map([['local', { id: 'local', local: true, name: 'This computer', home: os.homedir() }]]);
    this.jobs = new Map(); this.pending = new Map();
  }
  publicEndpoint(endpoint) { return { id: endpoint.id, name: endpoint.name, home: endpoint.home, local: !!endpoint.local, serverId: endpoint.serverId }; }
  endpoint(id) {
    const endpoint = this.endpoints.get(id);
    if (!endpoint || endpoint.closed) throw new Error('File connection closed; reconnect this pane');
    if (!endpoint.local) { this.ssh.authorize?.(this.store.get(endpoint.serverId), 'files'); if (this.ssh.securitySnapshot(this.store.get(endpoint.serverId)) !== endpoint.snapshot) throw new Error('Server profile or route changed. Reconnect the file pane.'); }
    return endpoint;
  }
  async open(serverId) {
    if (serverId === 'local') return this.publicEndpoint(this.endpoints.get('local'));
    if (this.pending.has(serverId)) return this.pending.get(serverId);
    const promise = this.openRemote(serverId).finally(() => this.pending.delete(serverId));
    this.pending.set(serverId, promise); return promise;
  }
  async openRemote(serverId) {
    const server = this.store.get(serverId), fingerprint = this.ssh.securitySnapshot(server);
    this.ssh.authorize?.(server, 'files');
    const cached = [...this.endpoints.values()].find(e => e.serverId === serverId && e.snapshot === fingerprint && !e.closed);
    if (cached) return this.publicEndpoint(cached);
    if ([...this.endpoints.values()].filter(e => !e.local && !e.closed).length >= 16) throw new Error('Maximum 16 file connections. Close an unused pane connection first.');
    let client, hostKey;
    try {
      client = await this.ssh.connect(server, undefined, { capability: 'files', onHostKey: key => { hostKey = key; } });
      const sftp = await new Promise((resolve, reject) => client.sftp((error, channel) => error ? reject(error) : resolve(channel)));
      sftp.on('error', () => {});
      const home = cleanPath(await invoke(sftp, 'realpath', '.'), false);
      const endpoint = { id: crypto.randomUUID(), serverId, snapshot: fingerprint, name: server.name, home, client, sftp, hostKey };
      const closed = () => { endpoint.closed = true; };
      client.on('close', closed); sftp.on('close', closed); sftp.on('error', closed);
      this.endpoints.set(endpoint.id, endpoint);
      this.store.audit('sftp.connected', server.name);
      return this.publicEndpoint(endpoint);
    } catch (error) { client?.destroy(); throw error; }
  }
  close(id) {
    const endpoint = this.endpoints.get(id);
    if (!endpoint || endpoint.local) return;
    if ([...this.jobs.values()].some(j => j.status === 'running' && (j.plan.from.id === id || j.plan.to.id === id))) throw new Error('A transfer is using this connection. Cancel it or wait before disconnecting.');
    endpoint.client.destroy(); this.endpoints.delete(id);
  }
  invalidateServer(serverId) {
    for (const job of this.jobs.values()) if (job.status === 'running' && [job.plan.from.serverId, job.plan.to.serverId].includes(serverId)) this.cancel(job.id);
    for (const [id, endpoint] of this.endpoints) if (endpoint.serverId === serverId) { endpoint.closed = true; endpoint.client.destroy(); this.endpoints.delete(id); }
  }
  async stat(endpoint, filename) { return endpoint.local ? fsp.lstat(filename) : invoke(endpoint.sftp, 'lstat', filename); }
  async exists(endpoint, filename) { try { return await this.stat(endpoint, filename); } catch (error) { if (missing(error)) return null; throw error; } }
  join(endpoint, directory, name) {
    basename(name);
    if (endpoint.local && process.platform === 'win32' && (/[<>:"|?*]/.test(name) || /[. ]$/.test(name) || /^(con|prn|aux|nul|com[1-9]|lpt[1-9])(?:\.|$)/i.test(name))) throw new Error('File name is not supported on Windows: ' + name);
    return endpoint.local ? path.join(directory, name) : path.posix.join(directory, name);
  }
  async listing(id, directory) {
    const endpoint = this.endpoint(id);
    directory = cleanPath(directory || endpoint.home, endpoint.local);
    const canonical = endpoint.local ? await fsp.realpath(directory) : await invoke(endpoint.sftp, 'realpath', directory);
    const items = endpoint.local ? await fsp.readdir(canonical) : await invoke(endpoint.sftp, 'readdir', canonical);
    if (items.length > 20000) throw new Error('Directory has more than 20,000 entries; open a smaller subdirectory');
    const entries = [];
    for (const item of items) {
      const name = endpoint.local ? item : item.filename;
      if (name === '.' || name === '..') continue;
      try {
        const stat = endpoint.local ? await fsp.lstat(this.join(endpoint, canonical, name)) : item.attrs;
        entries.push({ name, kind: kind(stat), size: stat.size, modified: endpoint.local ? stat.mtimeMs : stat.mtime * 1000 });
      } catch (error) { entries.push({ name, kind: 'unavailable', size: 0, error: error.message }); }
    }
    entries.sort((a, b) => Number(b.kind === 'folder') - Number(a.kind === 'folder') || a.name.localeCompare(b.name));
    const parent = endpoint.local ? path.dirname(canonical) : path.posix.dirname(canonical);
    return { path: canonical, parent, entries };
  }
  async mkdir(id, directory, name) {
    const endpoint = this.endpoint(id), filename = this.join(endpoint, cleanPath(directory, endpoint.local), name);
    if (endpoint.local) await fsp.mkdir(filename, { mode: 0o700 }); else await invoke(endpoint.sftp, 'mkdir', filename, { mode: 0o700 });
    this.store.audit('sftp.mkdir', endpoint.name); return filename;
  }
  async prepare(input) {
    const from = this.endpoint(input?.source?.endpointId), to = this.endpoint(input?.destination?.endpointId);
    if (from.local && to.local) throw new Error('Choose a server in at least one pane');
    const sourcePath = cleanPath(input.source.path, from.local), destinationPath = cleanPath(input.destination.path, to.local);
    const sourceBase = from.local ? await fsp.realpath(sourcePath) : await invoke(from.sftp, 'realpath', sourcePath);
    const destinationBase = to.local ? await fsp.realpath(destinationPath) : await invoke(to.sftp, 'realpath', destinationPath);
    if (!Array.isArray(input.source.names) || !input.source.names.length || input.source.names.length > 2000 || new Set(input.source.names).size !== input.source.names.length) throw new Error('Select 1–2000 distinct files or folders');
    const sameServer = !from.local && !to.local && (() => { const a = this.store.get(from.serverId), b = this.store.get(to.serverId); return a.host === b.host && a.port === b.port && a.username === b.username; })();
    if (sameServer) throw new Error('Server-to-server transfer requires two different server endpoints');
    const directories = [], files = [];
    let totalBytes = 0, visited = 0;
    const walk = async (src, dst, depth) => {
      if (++visited > 20000 || depth > 40) throw new Error('Transfer exceeds the 20,000-entry / 40-level limit');
      const stat = await this.stat(from, src), type = kind(stat), existing = await this.exists(to, dst);
      if (type === 'link' || type === 'special') throw new Error('Symbolic links and special files are not transferred: ' + src);
      if (type === 'file') {
        if (existing) throw new Error('Destination already exists; choose a different folder: ' + dst);
        if (!Number.isSafeInteger(stat.size) || stat.size < 0) throw new Error('File size is unsupported: ' + src);
        files.push({ src, dst, size: stat.size }); totalBytes += stat.size;
        if (!Number.isSafeInteger(totalBytes)) throw new Error('Total transfer size exceeds the supported range');
      } else {
        if (existing && !existing.isDirectory()) throw new Error('Destination is not a directory: ' + dst);
        directories.push({ dst, exists: !!existing });
        const children = from.local ? await fsp.readdir(src) : (await invoke(from.sftp, 'readdir', src)).map(e => e.filename);
        for (const name of children) if (name !== '.' && name !== '..') await walk(this.join(from, src, name), this.join(to, dst, name), depth + 1);
      }
    };
    for (const name of input.source.names) await walk(this.join(from, sourceBase, name), this.join(to, destinationBase, name), 0);
    const route = from.local || to.local ? 'device' : 'direct';
    if (route === 'direct') {
      const target = this.store.get(to.serverId);
      if (target.auth !== 'password') throw new Error('Direct transfer currently requires a saved password on the destination profile. Host/device transfers support every authentication method.');
      if (Buffer.byteLength(JSON.stringify(files)) > 1500000) throw new Error('This direct-transfer manifest is too large. Transfer fewer files at a time.');
      if (/[\r\n\0]/.test(this.vault.decrypt(target.secret))) throw new Error('Direct OpenSSH askpass does not support a multiline destination password');
    }
    return { from, to, sourceBase, destinationBase, files, directories, totalBytes, route };
  }
  view(job) { const { plan, controller, streams, activeRemote, ...safe } = job; return safe; }
  state() { return [...this.jobs.values()].map(job => this.view(job)); }
  update(job, force = false) {
    if (force || Date.now() - (job.lastUpdate || 0) > 150) { job.lastUpdate = Date.now(); this.emit('transfer', this.view(job)); }
  }
  start(plan) {
    this.endpoint(plan.from.id); this.endpoint(plan.to.id);
    if ([...this.jobs.values()].filter(j => j.status === 'running').length >= 2) throw new Error('Two transfers are already running. Wait or cancel one.');
    while (this.jobs.size >= 40) { const old = [...this.jobs.values()].find(j => j.status !== 'running'); if (!old) break; this.jobs.delete(old.id); }
    const job = { id: crypto.randomUUID(), status: 'running', route: plan.route, source: plan.from.name, destination: plan.to.name, destinationPath: plan.destinationBase,
      totalBytes: plan.totalBytes, bytes: 0, filesTotal: plan.files.length, filesDone: 0, current: '', createdAt: new Date().toISOString(), partialPaths: [], plan, controller: new AbortController() };
    this.jobs.set(job.id, job); this.store.audit('transfer.started', `${job.id}: ${plan.route}`); this.update(job, true);
    this.execute(job).catch(error => { job.status = job.controller.signal.aborted ? 'cancelled' : 'failed'; job.error = error.message; }).finally(() => {
      if (job.status === 'running') job.status = job.controller.signal.aborted ? 'cancelled' : 'completed'; job.finishedAt = new Date().toISOString();
      this.store.audit('transfer.finished', `${job.id}: ${job.status}`); this.update(job, true);
    });
    return this.view(job);
  }
  check(job) { if (job.controller.signal.aborted) throw new Error('Transfer cancelled'); }
  async reserve(endpoint, filename) {
    if (endpoint.local) {
      const handle = await fsp.open(filename, 'wx', 0o600);
      try { await handle.close(); } catch (error) { error.createdPath = filename; throw error; }
    } else {
      const handle = await invoke(endpoint.sftp, 'open', filename, 'wx', { mode: 0o600 });
      try { await invoke(endpoint.sftp, 'close', handle); } catch (error) { error.createdPath = filename; throw error; }
    }
  }
  async cleanup(job, filename) {
    try { if (job.plan.to.local) await fsp.unlink(filename); else await invoke(job.plan.to.sftp, 'unlink', filename); }
    catch (error) { if (!missing(error)) job.partialPaths.push(filename); }
  }
  async execute(job) {
    const { plan } = job;
    for (const dir of plan.directories) {
      this.check(job);
      if (!dir.exists) { if (plan.to.local) await fsp.mkdir(dir.dst, { mode: 0o700 }); else await invoke(plan.to.sftp, 'mkdir', dir.dst, { mode: 0o700 }); }
    }
    if (plan.route === 'direct') return this.direct(job);
    for (const file of plan.files) {
      this.check(job); job.current = file.src; this.update(job, true);
      let owned = false;
      try {
        await this.reserve(plan.to, file.dst); owned = true; this.check(job);
        const read = plan.from.local ? fs.createReadStream(file.src) : plan.from.sftp.createReadStream(file.src);
        const write = plan.to.local ? fs.createWriteStream(file.dst, { flags: 'r+' }) : plan.to.sftp.createWriteStream(file.dst, { flags: 'r+' });
        const progress = new Transform({ transform: (chunk, _encoding, callback) => { job.bytes += chunk.length; this.update(job); callback(null, chunk); } });
        await pipeline(read, progress, write, { signal: job.controller.signal });
        const stat = await this.stat(plan.to, file.dst);
        if (stat.size !== file.size) throw new Error('File size changed during transfer: ' + file.src);
        job.filesDone++; this.update(job, true);
      } catch (error) { if (owned || error.createdPath === file.dst) await this.cleanup(job, file.dst); throw error; }
    }
  }
  async direct(job) {
    const { plan } = job, destination = this.store.get(plan.to.serverId);
    if (!plan.files.length) return;
    const reserved = new Set(), completed = new Set();
    let client, channel, progressTimer, currentFile = null, completedBytes = 0, polling = false;
    const cancel = () => { if (channel) { channel.write('cancel\n'); setTimeout(() => client?.destroy(), 5000).unref(); } else client?.destroy(); };
    job.controller.signal.addEventListener('abort', cancel, { once: true });
    try {
      for (const file of plan.files) {
        this.check(job);
        try { await this.reserve(plan.to, file.dst); reserved.add(file.dst); }
        catch (error) { if (error.createdPath === file.dst) reserved.add(file.dst); throw error; }
      }
      this.check(job);
      // Use a separate source SSH connection so cancelling cannot close a terminal or file pane.
      client = await this.ssh.connect(this.store.get(plan.from.serverId), c => { client = c; }, { signal: job.controller.signal, capability: 'files' });
      this.check(job);
      const script = fs.readFileSync(path.join(__dirname, 'direct-transfer.py'), 'utf8');
      const hostKey = plan.to.hostKey;
      if (!Buffer.isBuffer(hostKey)) throw new Error('Reconnect the destination to verify its SSH host key');
      const keyType = hostKey.subarray(4, 4 + hostKey.readUInt32BE(0)).toString('ascii');
      const hostLabel = destination.port === 22 ? destination.host : `[${destination.host}]:${destination.port}`;
      const config = { host: destination.host, port: destination.port, username: destination.username, password: this.vault.decrypt(destination.secret),
        knownHost: `${hostLabel} ${keyType} ${hostKey.toString('base64')}`, files: plan.files };
      progressTimer = setInterval(async () => {
        if (polling || !currentFile || job.controller.signal.aborted) return;
        const file = currentFile; polling = true;
        try { const stat = await this.stat(plan.to, file.dst); if (currentFile === file && job.status === 'running') { job.bytes = completedBytes + Math.min(file.size, stat.size); this.update(job); } }
        catch {} finally { polling = false; }
      }, 750);
      progressTimer.unref();
      await new Promise((resolve, reject) => {
        let done = false, buffer = '', remoteError = '', sawDone = false;
        const finish = error => { if (done) return; done = true; error ? reject(error) : resolve(); };
        client.once('error', finish); client.once('close', () => finish(new Error('Source connection closed during direct transfer')));
        client.exec('python3 -u -c ' + quote(script), (error, stream) => {
          if (error) { finish(error); return; }
          channel = stream;
          stream.on('error', finish);
          stream.stderr.on('data', chunk => { remoteError = (remoteError + chunk.toString()).slice(-8192); });
          stream.on('data', chunk => {
            buffer += chunk.toString('utf8');
            if (buffer.length > 65536) { finish(new Error('Invalid direct-transfer response')); client.destroy(); return; }
            let end;
            while ((end = buffer.indexOf('\n')) >= 0) {
              const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
              try {
                const event = JSON.parse(line), file = plan.files[event.index];
                if (event.event === 'file' && file) { job.current = file.src; currentFile = file; }
                else if (event.event === 'completed' && file && !completed.has(file.dst)) { completed.add(file.dst); job.filesDone++; completedBytes += file.size; job.bytes = completedBytes; currentFile = null; }
                else if (event.event === 'error') remoteError = String(event.message).slice(0, 8192);
                else if (event.event === 'done') sawDone = true;
                this.update(job, true);
              } catch { remoteError = 'Invalid direct-transfer response'; }
            }
          });
          stream.on('close', code => finish(code === 0 && sawDone && completed.size === plan.files.length ? undefined : new Error(remoteError || 'Direct transfer failed or was cancelled')));
          if (job.controller.signal.aborted) { cancel(); return; }
          // Credentials are SSH channel data, not source command arguments, environment variables or files.
          stream.write(JSON.stringify(config) + '\n'); config.password = '';
        });
      });
      for (const file of plan.files) if ((await this.stat(plan.to, file.dst)).size !== file.size) {
        completed.delete(file.dst); job.filesDone--; job.bytes = Math.max(0, job.bytes - file.size);
        throw new Error('Destination size mismatch: ' + file.dst);
      }
    } finally {
      clearInterval(progressTimer); job.controller.signal.removeEventListener('abort', cancel); client?.destroy();
      for (const filename of reserved) if (!completed.has(filename)) await this.cleanup(job, filename);
    }
  }
  cancel(id) { const job = this.jobs.get(id); if (job?.status === 'running') { job.controller.abort(); this.update(job, true); } }
  shutdown() { for (const job of this.jobs.values()) this.cancel(job.id); for (const endpoint of this.endpoints.values()) endpoint.client?.destroy(); }
}
module.exports = { Files, cleanPath, basename, invoke };
