const crypto = require('node:crypto');
const { promisify } = require('node:util');
const { normalizeServer, publicServer } = require('./core.cjs');
const { normalizeVPN, normalizeRule } = require('./network-config.cjs');
const { validatePrivateKey } = require('./shared-credentials.cjs');
const scrypt = promisify(crypto.scrypt), FORMAT = 'connector-backup', AAD = Buffer.from('connector-backup/v1');
const limit = 10 * 1024 * 1024;
function phrase(value) { if (typeof value !== 'string' || value.length < 12 || value.length > 1024) throw new Error('Use a backup passphrase of 12–1024 characters'); return value; }
async function key(passphrase, salt) { return scrypt(phrase(passphrase), salt, 32, { N: 32768, r: 8, p: 1, maxmem: 64 * 1024 * 1024 }); }
function validate(payload, encrypted) {
  if (!payload || payload.format !== 'connector-profiles' || payload.version !== 1 || !Array.isArray(payload.servers) || !Array.isArray(payload.vpns) || !Array.isArray(payload.rules)) throw new Error('Unsupported Connector backup format');
  if (payload.servers.length > 2000 || payload.vpns.length > 200 || payload.rules.length > 2000) throw new Error('Backup profile limit exceeded');
  const ids = new Set(), vpnIds = new Set(), serverIds = new Set();
  for (const vpn of payload.vpns) {
    normalizeVPN(vpn, vpn.id); if (typeof vpn.id !== 'string' || ids.has(vpn.id)) throw new Error('Duplicate or invalid profile ID'); ids.add(vpn.id); vpnIds.add(vpn.id);
    if (!encrypted && (vpn.password || vpn.psk || vpn.passwordSecret || vpn.pskSecret)) throw new Error('Unencrypted backup cannot contain credentials');
    for (const secret of [vpn.password, vpn.psk]) if (secret !== undefined && (typeof secret !== 'string' || secret.length > 8192 || /[\r\n\0]/.test(secret))) throw new Error('Invalid VPN credential in backup');
  }
  for (const server of payload.servers) {
    normalizeServer(server, server.id); if (typeof server.id !== 'string' || ids.has(server.id)) throw new Error('Duplicate or invalid profile ID'); ids.add(server.id); serverIds.add(server.id);
    if (server.routeMode === 'vpn' && !vpnIds.has(server.vpnId)) throw new Error('Backup is missing a referenced VPN profile');
    if (!encrypted && (server.credential || server.secret || server.privateKey || server.privateKeySecret)) throw new Error('Unencrypted backup cannot contain credentials');
    if (server.privateKey !== undefined) validatePrivateKey(server.privateKey, server.credential);
    if (server.credential !== undefined && (typeof server.credential !== 'string' || server.credential.length > 8192)) throw new Error('Invalid SSH credential in backup');
  }
  for (const rule of payload.rules) {
    const normalized = normalizeRule(rule, rule.id);
    if (typeof rule.id !== 'string' || ids.has(rule.id)) throw new Error('Duplicate or invalid rule ID'); ids.add(rule.id);
    if (normalized.vpnId && !vpnIds.has(normalized.vpnId)) throw new Error('Backup is missing a rule VPN');
    if (normalized.serverId && !serverIds.has(normalized.serverId)) throw new Error('Backup is missing a rule connection');
  }
  return payload;
}
async function encode(payload, passphrase) {
  validate(payload, !!passphrase);
  if (!passphrase) return JSON.stringify(payload, null, 2);
  const salt = crypto.randomBytes(16), nonce = crypto.randomBytes(12), derived = await key(passphrase, salt);
  try {
    const cipher = crypto.createCipheriv('aes-256-gcm', derived, nonce); cipher.setAAD(AAD);
    const ciphertext = Buffer.concat([cipher.update(JSON.stringify(payload), 'utf8'), cipher.final()]);
    return JSON.stringify({ format: FORMAT, version: 1, encrypted: true, kdf: 'scrypt-32768-8-1', cipher: 'aes-256-gcm', salt: salt.toString('base64'), nonce: nonce.toString('base64'), tag: cipher.getAuthTag().toString('base64'), ciphertext: ciphertext.toString('base64') }, null, 2);
  } finally { derived.fill(0); }
}
async function decode(content, passphrase) {
  if (typeof content !== 'string' || Buffer.byteLength(content) > limit) throw new Error('Backup exceeds 10 MiB');
  let value; try { value = JSON.parse(content); } catch { throw new Error('Invalid backup JSON'); }
  if (value.format !== FORMAT) return validate(value, false);
  if (value.version !== 1 || value.encrypted !== true || value.kdf !== 'scrypt-32768-8-1' || value.cipher !== 'aes-256-gcm') throw new Error('Unsupported backup encryption');
  const field = (name, length) => { if (typeof value[name] !== 'string' || !/^[A-Za-z0-9+/]*={0,2}$/.test(value[name])) throw new Error('Invalid backup encryption field'); const b = Buffer.from(value[name], 'base64'); if (length && b.length !== length) throw new Error('Invalid backup encryption field'); return b; };
  const salt = field('salt', 16), nonce = field('nonce', 12), tag = field('tag', 16), ciphertext = field('ciphertext');
  const derived = await key(passphrase, salt);
  try {
    const decipher = crypto.createDecipheriv('aes-256-gcm', derived, nonce); decipher.setAAD(AAD); decipher.setAuthTag(tag);
    let data; try { data = Buffer.concat([decipher.update(ciphertext), decipher.final()]); } catch { throw new Error('Incorrect backup passphrase or damaged/tampered backup'); }
    try { let payload; try { payload = JSON.parse(data.toString('utf8')); } catch { throw new Error('Invalid decrypted backup payload'); } return validate(payload, true); } finally { data.fill(0); }
  } finally { derived.fill(0); }
}
class Backups {
  constructor(store, network) { this.store = store; this.network = network; }
  payload(options = {}) {
    const includeSecrets = options.includeSecrets === true, servers = options.servers !== false ? this.store.all(true).filter(p => !p.shared) : [], allVPNs = this.network.vpns(true).filter(p => !p.shared);
    const serverIds = new Set(servers.map(s => s.id));
    const rules = this.network.rules().filter(rule => (!rule.serverId || serverIds.has(rule.serverId)) && (options.servers !== false || rule.action === 'vpn'));
    const vpnIds = new Set(options.vpns !== false ? allVPNs.map(v => v.id) : []);
    for (const s of servers) if (s.vpnId) vpnIds.add(s.vpnId);
    for (const r of rules) if (r.vpnId) vpnIds.add(r.vpnId);
    const vpns = allVPNs.filter(v => vpnIds.has(v.id)).map(v => {
      const { passwordSecret, pskSecret, ...safe } = v;
      if (includeSecrets) { if (passwordSecret) safe.password = this.store.vault.decrypt(passwordSecret); if (pskSecret) safe.psk = this.store.vault.decrypt(pskSecret); }
      return safe;
    });
    return { format: 'connector-profiles', version: 1, createdAt: new Date().toISOString(), servers: servers.map(s => { const { secret, privateKeySecret, agentDelegate, ...safe } = s; if (includeSecrets && secret) safe.credential = this.store.vault.decrypt(secret); if (includeSecrets && privateKeySecret) safe.privateKey = this.store.vault.decrypt(privateKeySecret); return safe; }), vpns, rules };
  }
  async export(options) {
    if (options.includeSecrets && !options.passphrase) throw new Error('A backup passphrase is required when exporting credentials');
    if (options.servers === false && options.vpns === false) throw new Error('Choose connections and/or VPNs to export');
    const payload = this.payload(options); return encode(payload, options.passphrase || '');
  }
  preview(payload) { return { servers: payload.servers.length, vpns: payload.vpns.length, rules: payload.rules.length, plainVPNs: payload.vpns.filter(v => v.protocol === 'l2tp').length, credentials: payload.servers.filter(s => s.credential).length + payload.vpns.filter(v => v.password || v.psk).length,
    missingCredentials: payload.servers.filter(s => s.auth === 'password' && !s.credential).length + payload.vpns.filter(v => !v.password || (v.protocol !== 'l2tp' && !v.psk)).length }; }
  import(payload, enableRules = false) {
    validate(payload, true);
    const ids = new Map([...payload.vpns, ...payload.servers, ...payload.rules].map(value => [value.id, crypto.randomUUID()]));
    const encrypt = plain => { if (!plain) return undefined; if (!this.store.vault.available()) throw new Error('Unlock the OS credential vault before importing credentials'); return this.store.vault.encrypt(plain); };
    // Validate and encrypt everything before beginning a mutation.
    const vpns = payload.vpns.map(v => ({ ...normalizeVPN(v, ids.get(v.id)), passwordSecret: encrypt(v.password), pskSecret: v.protocol === 'l2tp' ? undefined : encrypt(v.psk) }));
    const servers = payload.servers.map(s => ({ ...normalizeServer({ ...s, vpnId: s.vpnId ? ids.get(s.vpnId) : '' }, ids.get(s.id)), secret: encrypt(s.credential), ...(s.privateKey ? { privateKeySecret:encrypt(s.privateKey) } : {}) }));
    const rules = payload.rules.map(r => normalizeRule({ ...r, enabled: enableRules && r.enabled !== false, vpnId: r.vpnId ? ids.get(r.vpnId) : '', serverId: r.serverId ? ids.get(r.serverId) : '' }, ids.get(r.id)));
    const before = this.store.db.export(), Database = this.store.db.constructor;
    try {
      this.store.db.run('BEGIN TRANSACTION');
      for (const [table, list] of [['vpns', vpns], ['servers', servers], ['route_rules', rules]]) for (const record of list) this.store.db.run(`INSERT INTO ${table} VALUES (?,?)`, [record.id, JSON.stringify(record)]);
      this.store.db.run('INSERT INTO audit(time,action,detail) VALUES (?,?,?)', [new Date().toISOString(), 'backup.imported', `${servers.length} connections, ${vpns.length} VPNs, ${rules.length} rules`]);
      this.store.db.run('COMMIT'); this.store.save();
    } catch (error) { try { this.store.db.close(); } catch {} this.store.db = new Database(before); throw error; }
    return { servers: servers.map(publicServer), vpns: vpns.length, rules: rules.length };
  }
}
module.exports = { Backups, encode, decode, validate, limit };
