const { Client } = require('ssh2');
const fs = require('node:fs');
const crypto = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');

class SSH {
  constructor(store, vault, confirmHost, emit, routes) { this.store = store; this.vault = vault; this.confirmHost = confirmHost; this.emit = emit; this.routes = routes; this.sessions = new Map(); this.hostChecks = new Map(); }
  securitySnapshot(server) { const { distro, ...security } = server; return this.routes ? require('./core.cjs').snapshot({ server: security, route: this.routes.fingerprint(server) }) : require('./core.cjs').snapshot(security); }
  async checkHost(server, key, routeKey = 'direct', routeName = 'Direct') {
    const address = (routeKey === 'direct' ? '' : routeKey + '/') + `[${server.host}]:${server.port}`;
    const fingerprint = 'SHA256:' + crypto.createHash('sha256').update(key).digest('base64').replace(/=+$/, '');
    const known = this.store.fingerprint(address);
    if (known) {
      if (known !== fingerprint) this.emit('notice', { message: `HOST KEY CHANGED for ${address}. Connection blocked. Verify the server outside this application.` });
      return known === fingerprint;
    }
    const checkId = `${address}/${fingerprint}`;
    if (!this.hostChecks.has(checkId)) {
      const check = this.confirmHost({ ...server, routeName }, fingerprint).then(ok => { if (ok) this.store.pin(address, fingerprint); return ok; }).finally(() => this.hostChecks.delete(checkId));
      this.hostChecks.set(checkId, check);
    }
    return this.hostChecks.get(checkId);
  }
  async connect(server, register, options = {}) {
    this.authorize?.(server, options.capability || 'terminal');
    const expected = this.routes ? this.securitySnapshot(server) : null;
    const route = this.routes ? await this.routes.dial(server, options.signal) : null;
    if (this.routes) { try { if (this.securitySnapshot(this.store.get(server.id)) !== expected) throw new Error('Connection profile or route changed during setup'); } catch (error) { route?.socket.destroy(); throw error; } }
    if (options.signal?.aborted) { route?.socket.destroy(); throw new Error('Connection cancelled'); }
    return new Promise((resolve, reject) => {
      const client = new Client();
      if (register) register(client);
      let settled = false;
      const fail = error => { if (!settled) { settled = true; client.destroy(); route?.socket.destroy(); reject(error); } };
      client.on('error', fail);
      client.on('close', () => fail(new Error('SSH connection closed')));
      const cancel = () => { client.destroy(); fail(new Error('Connection cancelled')); };
      options.signal?.addEventListener('abort', cancel, { once: true });
      client.once('close', () => options.signal?.removeEventListener('abort', cancel));
      client.once('ready', () => { try { this.authorize?.(this.store.get(server.id), options.capability || 'terminal'); settled = true; resolve(client); } catch (error) { fail(error); } });
      try {
        const config = { host: server.host, port: server.port, username: server.username,
          readyTimeout: 25000, keepaliveInterval: 15000, keepaliveCountMax: 3,
          hostVerifier: (key, callback) => { this.checkHost(server, key, route?.key, route?.name).then(ok => { if (ok) options.onHostKey?.(key); callback(ok); }).catch(() => callback(false)); } };
        if (route) config.sock = route.socket;
        if (server.auth === 'agent') config.agent = this.sharedAgent?.(server) || process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : undefined);
        if (server.auth === 'agent' && !config.agent) throw new Error('SSH agent is unavailable. Set SSH_AUTH_SOCK or select a private key.');
        if (server.auth === 'key') { if (server.keySource === 'vault' && !server.privateKeySecret) throw new Error('Private key material was not shared'); config.privateKey = server.keySource === 'vault' ? this.vault.decrypt(server.privateKeySecret) : fs.readFileSync(server.keyPath); if (server.secret) config.passphrase = this.vault.decrypt(server.secret); }
        if (server.auth === 'password') { if (!server.secret) throw new Error('Configure the saved SSH password before connecting'); config.password = this.vault.decrypt(server.secret); }
        client.connect(config);
        route?.socket.resume();
      } catch (error) { fail(error); }
    });
  }
  async open(id, cols = 100, rows = 30) {
    if (!Number.isInteger(cols) || cols < 2 || cols > 1000 || !Number.isInteger(rows) || rows < 1 || rows > 500) throw new Error('Invalid terminal dimensions');
    if (this.sessions.size >= 24) throw new Error('Maximum 24 terminal sessions');
    const server = this.store.get(id);
    const sessionId = crypto.randomUUID();
    const entry = { client: null, stream: null, serverId: id, name: server.name, cols, rows, controller: new AbortController() };
    this.sessions.set(sessionId, entry);
    try {
      const client = await this.connect(server, c => { entry.client = c; }, { signal: entry.controller.signal });
      const stream = await new Promise((resolve, reject) => client.shell({ term: 'xterm-256color', cols, rows }, (e, s) => e ? reject(e) : resolve(s)));
      entry.stream = stream;
      const decoder = new StringDecoder('utf8');
      stream.on('data', data => this.emit('terminal', { sessionId, data: decoder.write(data) }));
      stream.stderr.on('data', data => this.emit('terminal', { sessionId, data: data.toString('utf8') }));
      const closed = () => { if (this.sessions.delete(sessionId)) { this.emit('terminal', { sessionId, closed: true }); client.end(); } };
      stream.on('close', closed); client.on('close', closed);
      client.on('error', error => this.emit('terminal', { sessionId, data: `\r\nConnection error: ${error.message}\r\n` }));
      this.store.audit('ssh.connected', server.name);
      this.detectDistro(client, server.id);
      return { sessionId, serverId: id, name: server.name };
    } catch (error) { this.close(sessionId); throw error; }
  }
  async openMany(ids, onResult) {
    if (!Array.isArray(ids) || !ids.length || ids.length > 24 || new Set(ids).size !== ids.length) throw new Error('Select 1–24 distinct servers');
    if (this.sessions.size + ids.length > 24) throw new Error('Selected servers exceed the 24-session limit. Close unused terminals first.');
    ids.forEach(id => this.store.get(id));
    let cursor = 0;
    const results = new Array(ids.length);
    await Promise.all(Array.from({ length: Math.min(4, ids.length) }, async () => {
      while (cursor < ids.length) {
        const index = cursor++, serverId = ids[index];
        try { results[index] = { serverId, session: await this.open(serverId) }; }
        catch (error) { results[index] = { serverId, error: error.message }; }
        onResult?.(results[index]);
      }
    }));
    return results;
  }
  write(id, data) { if (typeof data !== 'string' || Buffer.byteLength(data) > 65536) throw new Error('Invalid terminal input'); this.sessions.get(id)?.stream?.write(data); }
  resize(id, cols, rows) { if (!Number.isInteger(cols) || !Number.isInteger(rows) || cols < 2 || cols > 1000 || rows < 1 || rows > 500) return; const s = this.sessions.get(id); if (s) { s.cols = cols; s.rows = rows; s.stream?.setWindow(rows, cols, 0, 0); this.emit('terminal-size', { sessionId: id, cols, rows }); } }
  close(id) { const s = this.sessions.get(id); if (s) { this.sessions.delete(id); s.controller?.abort(); s.stream?.close(); s.client?.destroy(); this.emit('terminal', { sessionId: id, closed: true }); } }
  closeServer(id) { for (const [sessionId, s] of this.sessions) if (s.serverId === id) this.close(sessionId); }
  detectDistro(client, id) {
    const command = "cat /etc/os-release 2>/dev/null || uname -s";
    client.exec(command, (error, stream) => {
      if (error) return; let output = '', bytes = 0;
      const timer = setTimeout(() => stream.close(), 3000); timer.unref();
      stream.on('error', () => {}); stream.on('data', data => { bytes += data.length; if (bytes <= 16384) output += data.toString(); else stream.close(); });
      stream.on('close', () => { clearTimeout(timer); const distro = require('./distro.cjs').parseDistro(output); if (!distro) return;
        try { const server = this.store.get(id); if (server.distro === distro) return; server.distro = distro; this.store.db.run('UPDATE servers SET data=? WHERE id=?', [JSON.stringify(server), id]); this.store.save(); this.emit('distro', { serverId: id, distro }); } catch {} });
    });
  }
  closeAll() { for (const id of this.sessions.keys()) this.close(id); }
  async exec(server, command, timeout, signal, output, options = {}) {
    let client, channel, timer;
    const connectionAbort = new AbortController();
    let truncated = false, size = 0, timedOut = false;
    const limit = 256 * 1024;
    const abort = () => { connectionAbort.abort(); try { channel?.signal('TERM'); } catch {} client?.destroy(); };
    signal.addEventListener('abort', abort, { once: true });
    const stdoutDecoder = new StringDecoder('utf8'), stderrDecoder = new StringDecoder('utf8');
    try {
      if (signal.aborted) throw new Error('Cancelled before connection');
      timer = setTimeout(() => { timedOut = true; abort(); }, timeout * 1000);
      client = await this.connect(server, c => { client = c; }, { signal: connectionAbort.signal, capability: 'exec' });
      if (signal.aborted || timedOut) throw new Error(timedOut ? 'Timed out' : 'Cancelled');
      return await new Promise((resolve, reject) => {
        let done = false;
        const finish = result => { if (!done) { done = true; resolve({ ...result, truncated }); } };
        client.once('error', reject);
        client.once('close', () => finish({ status: timedOut ? 'timed-out' : signal.aborted ? 'cancelled' : 'disconnected', exitCode: null }));
        client.exec(command, options.interactive ? { pty: { term: 'xterm-256color', cols: 100, rows: 16 } } : {}, (err, stream) => {
          if (err) { reject(err); return; }
          channel = stream;
          const accept = (chunk, stderr) => {
            const remaining = limit - size;
            if (chunk.length > remaining) truncated = true;
            if (remaining <= 0) return;
            const accepted = chunk.subarray(0, remaining); size += accepted.length;
            output((stderr ? stderrDecoder : stdoutDecoder).write(accepted), stderr);
          };
          stream.on('data', b => accept(b, false)); stream.stderr.on('data', b => accept(b, true));
          stream.on('error', reject);
          stream.on('close', (code, remoteSignal) => {
            output(stdoutDecoder.end(), false); output(stderrDecoder.end(), true);
            finish({ status: timedOut ? 'timed-out' : signal.aborted ? 'cancelled' : code === 0 ? 'succeeded' : 'failed', exitCode: code ?? null, signal: remoteSignal || null });
          });
          if (signal.aborted || timedOut) { abort(); return; }
          options.onReady?.({
            write: data => { if (typeof data !== 'string' || Buffer.byteLength(data) > 65536) throw new Error('Invalid terminal input'); stream.write(data); },
            resize: (cols, rows) => { if (Number.isInteger(cols) && cols >= 2 && cols <= 1000 && Number.isInteger(rows) && rows >= 1 && rows <= 500) stream.setWindow(rows, cols, 0, 0); }
          });
        });
      });
    } catch (error) {
      if (timedOut) return { status: 'timed-out', exitCode: null, truncated };
      if (signal.aborted) return { status: 'cancelled', exitCode: null, truncated };
      throw error;
    } finally { clearTimeout(timer); signal.removeEventListener('abort', abort); client?.destroy(); }
  }
}
module.exports = { SSH };
