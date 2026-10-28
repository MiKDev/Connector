const fs = require('node:fs');
const path = require('node:path');
const { utils } = require('ssh2');
const { STATUS_CODE: STATUS } = utils.sftp;
function openFlags(flags) {
  // OpenSSH may use WRITE|CREAT without TRUNC. ssh2.flagsToString only maps
  // JavaScript's named flag combinations and returns null for that valid case.
  const c=fs.constants,access=flags&3;let result=access===3?c.O_RDWR:access===2?c.O_WRONLY:c.O_RDONLY;
  for(const [bit,value]of [[4,c.O_APPEND],[8,c.O_CREAT],[16,c.O_TRUNC],[32,c.O_EXCL]])if(flags&bit)result|=value;
  return result;
}
function attachSFTP(session, root) {
  session.on('sftp', accept => {
    const channel = accept(), handles = new Map(); let counter = 0;
    const resolvePath = value => {
      const normalized = value.replace(/\\/g, '/');
      const result = path.resolve(normalized.startsWith(root.replace(/\\/g, '/')) ? value : path.join(root, normalized.replace(/^\/+/, '')));
      if (result !== root && !result.startsWith(root + path.sep)) throw Object.assign(new Error('Outside fixture root'), { code: 'EACCES' });
      return result;
    };
    const attributes = stat => ({ mode: stat.mode, uid: stat.uid, gid: stat.gid, size: stat.size, atime: Math.floor(stat.atimeMs / 1000), mtime: Math.floor(stat.mtimeMs / 1000) });
    const error = (id, e) => { if(process.env.CONNECTOR_SFTP_FIXTURE_DEBUG)console.error('SFTP fixture request failed:',id,e.code||'',e.message);channel.status(id, e.code === 'ENOENT' ? STATUS.NO_SUCH_FILE : e.code === 'EACCES' ? STATUS.PERMISSION_DENIED : STATUS.FAILURE, e.code || e.message); };
    const wrap = fn => async (...args) => { try { await fn(...args); } catch (e) { error(args[0], e); } };
    const save = item => { const handle = Buffer.alloc(4); handle.writeUInt32BE(++counter); handles.set(counter, item); return handle; };
    const get = handle => { const item = handles.get(handle.readUInt32BE()); if (!item) throw new Error('Invalid handle'); return item; };
    channel.on('error', () => {});
    // The ssh2 SFTP adapter is not a process: model an OpenSSH subsystem's
    // successful exit when its client closes stdin, rather than leaving scp
    // waiting forever for the remote session to finish.
    session.once('end',()=>{if(channel.outgoing.state==='open'){channel._protocol.exitStatus(channel.outgoing.id,0);channel.end();}});
    channel.on('REALPATH', wrap(async (id, filename) => {
      const real = await fs.promises.realpath(resolvePath(filename === '.' ? '/' : filename));
      const virtual = process.platform === 'win32' ? '/' + path.relative(root, real).replace(/\\/g, '/') : real;
      channel.name(id, [{ filename: virtual || '/', longname: virtual || '/', attrs: {} }]);
    }));
    for (const method of ['STAT', 'LSTAT']) channel.on(method, wrap(async (id, filename) => channel.attrs(id, attributes(await fs.promises[method === 'STAT' ? 'stat' : 'lstat'](resolvePath(filename))))));
    channel.on('OPENDIR', wrap(async (id, filename) => { const dir = resolvePath(filename); const names = await fs.promises.readdir(dir); channel.handle(id, save({ dir, names, cursor: 0 })); }));
    channel.on('READDIR', wrap(async (id, handle) => {
      const item = get(handle); if (item.cursor >= item.names.length) { channel.status(id, STATUS.EOF); return; }
      const batch = item.names.slice(item.cursor, item.cursor + 40); item.cursor += batch.length;
      const names = await Promise.all(batch.map(async name => ({ filename: name, longname: name, attrs: attributes(await fs.promises.lstat(path.join(item.dir, name))) })));
      channel.name(id, names);
    }));
    channel.on('OPEN', wrap(async (id, filename, flags, attrs) => { const file = await fs.promises.open(resolvePath(filename), openFlags(flags), attrs.mode || 0o600); channel.handle(id, save({ file })); }));
    channel.on('CLOSE', wrap(async (id, handle) => { const item = get(handle); if (item.file) await item.file.close(); handles.delete(handle.readUInt32BE()); channel.status(id, STATUS.OK); }));
    channel.on('READ', wrap(async (id, handle, offset, length) => { const data = Buffer.alloc(Math.min(length, 65536)); const { bytesRead } = await get(handle).file.read(data, 0, data.length, offset); if (!bytesRead) channel.status(id, STATUS.EOF); else channel.data(id, data.subarray(0, bytesRead)); }));
    channel.on('WRITE', wrap(async (id, handle, offset, data) => { await get(handle).file.write(data, 0, data.length, offset); channel.status(id, STATUS.OK); }));
    channel.on('FSTAT', wrap(async (id, handle) => channel.attrs(id, attributes(await get(handle).file.stat()))));
    channel.on('MKDIR', wrap(async (id, filename, attrs) => { await fs.promises.mkdir(resolvePath(filename), { mode: attrs.mode || 0o700 }); channel.status(id, STATUS.OK); }));
    channel.on('REMOVE', wrap(async (id, filename) => { await fs.promises.unlink(resolvePath(filename)); channel.status(id, STATUS.OK); }));
    channel.on('SETSTAT', (id) => channel.status(id, STATUS.OK));
    channel.on('FSETSTAT', (id) => channel.status(id, STATUS.OK));
    channel.on('close', () => { for (const item of handles.values()) item.file?.close().catch(() => {}); handles.clear(); });
  });
}
module.exports = { attachSFTP };
