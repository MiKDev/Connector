const fs = require('node:fs');
const path = require('node:path');
const initSqlJs = require('sql.js');
const { normalizeServer, publicServer } = require('./core.cjs');

class Store {
  static async open(directory, vault) {
    const SQL = await initSqlJs({ locateFile: file => path.join(path.dirname(require.resolve('sql.js')), file) });
    fs.mkdirSync(directory, { recursive: true, mode: 0o700 });
    const filename = path.join(directory, 'connector.sqlite');
    const db = fs.existsSync(filename) ? new SQL.Database(fs.readFileSync(filename)) : new SQL.Database();
    db.run('CREATE TABLE IF NOT EXISTS servers (id TEXT PRIMARY KEY, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS hosts (address TEXT PRIMARY KEY, fingerprint TEXT NOT NULL); CREATE TABLE IF NOT EXISTS audit (id INTEGER PRIMARY KEY AUTOINCREMENT, time TEXT, action TEXT, detail TEXT);');
    return new Store(db, filename, vault);
  }
  constructor(db, filename, vault) { this.db = db; this.filename = filename; this.vault = vault; }
  rows(sql, params = []) { const s = this.db.prepare(sql); try { s.bind(params); const rows = []; while (s.step()) rows.push(s.getAsObject()); return rows; } finally { s.free(); } }
  save() {
    const temporary = `${this.filename}.tmp`;
    fs.writeFileSync(temporary, Buffer.from(this.db.export()), { mode: 0o600 });
    fs.renameSync(temporary, this.filename);
  }
  all(internal = false) { return this.rows('SELECT data FROM servers ORDER BY id').map(r => JSON.parse(r.data)).map(s => internal ? s : publicServer(s)); }
  get(id) { const row = this.rows('SELECT data FROM servers WHERE id=?', [id])[0]; if (!row) throw new Error('Server no longer exists'); return JSON.parse(row.data); }
  put(input, id) {
    const previous = id ? this.get(id) : undefined;
    if (previous?.shared) throw new Error('Shared profiles are managed by their owner');
    const server = normalizeServer(input, id);
    if (server.auth === 'key' && server.keySource === 'vault') { if (!previous?.privateKeySecret) throw new Error('Import or persist a shared private key first'); server.privateKeySecret = previous.privateKeySecret; }
    if (previous?.agentDelegate && server.auth === 'agent') {
      if (['host','port','username'].some(k=>server[k]!==previous[k])) throw new Error('Delegated agent endpoints are managed by their owner; select another authentication method to change the endpoint');
      server.agentDelegate = previous.agentDelegate;
    }
    if (previous?.host === server.host && previous?.port === server.port && previous.distro) server.distro = previous.distro;
    if (input.secret && typeof input.secret !== 'string') throw new Error('Invalid credential');
    if (input.secret && input.secret.length > 8192) throw new Error('Credential too long');
    if (server.auth !== 'agent') {
      if (input.secret) {
        if (!this.vault.available()) throw new Error('Secure OS credential storage is unavailable. Use SSH agent or an unencrypted key file instead.');
        server.secret = this.vault.encrypt(input.secret);
      } else if (previous && previous.auth === server.auth && previous.keyPath === server.keyPath) server.secret = previous.secret;
      if (server.auth === 'password' && !server.secret) throw new Error('Password required');
    }
    this.db.run('INSERT OR REPLACE INTO servers VALUES (?,?)', [server.id, JSON.stringify(server)]);
    this.audit(previous ? 'server.updated' : 'server.added', server.name);
    return publicServer(server);
  }
  remove(id) { const s = this.get(id); if (s.shared) throw new Error('Remove the sharing server to remove managed profiles'); this.db.run('DELETE FROM servers WHERE id=?', [id]); this.audit('server.removed', s.name); }
  duplicate(id) {
    const previous = this.get(id); if (previous.shared) throw new Error('Shared profiles cannot be copied or exported');
    const value = { ...previous, id: require('node:crypto').randomUUID(), name: (previous.name.slice(0, 73) + ' (copy)'), updatedAt: new Date().toISOString() };
    this.db.run('INSERT INTO servers VALUES (?,?)', [value.id, JSON.stringify(value)]); this.audit('server.copied', previous.name); return publicServer(value);
  }
  pin(address, fingerprint) { this.db.run('INSERT OR REPLACE INTO hosts VALUES (?,?)', [address, fingerprint]); this.audit('host.trusted', address); }
  fingerprint(address) { return this.rows('SELECT fingerprint FROM hosts WHERE address=?', [address])[0]?.fingerprint; }
  audit(action, detail) {
    this.db.run('INSERT INTO audit(time,action,detail) VALUES (?,?,?)', [new Date().toISOString(), action, String(detail).slice(0, 500)]);
    this.db.run('DELETE FROM audit WHERE id NOT IN (SELECT id FROM audit ORDER BY id DESC LIMIT 1000)');
    this.save();
  }
  history() { return this.rows('SELECT time,action,detail FROM audit ORDER BY id DESC LIMIT 100'); }
}
module.exports = { Store };
