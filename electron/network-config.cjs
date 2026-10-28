const crypto = require('node:crypto');
const net = require('node:net');
const ipaddr = require('ipaddr.js');
const { text } = require('./core.cjs');
function host(value) { value = text(value, 'VPN gateway', 253); if (!net.isIP(value) && !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(value)) throw new Error('Invalid VPN gateway hostname/address'); return value; }
function cidr(value) { try { const [address, prefix] = ipaddr.parseCIDR(value); const bytes = address.toByteArray().map((byte, index) => { const bits = prefix - index * 8; return byte & (bits >= 8 ? 255 : bits > 0 ? (255 << (8 - bits)) & 255 : 0); }); return ipaddr.fromByteArray(bytes).toNormalizedString() + '/' + prefix; } catch { throw new Error('Invalid network prefix: ' + value); } }
function normalizeVPN(input, id = crypto.randomUUID()) {
  if (!input || typeof input !== 'object') throw new Error('VPN profile required');
  const protocol = input.protocol || 'l2tp-ipsec-psk';
  if (!['l2tp-ipsec-psk','l2tp'].includes(protocol)) throw new Error('Unsupported VPN protocol');
  const mtu = Number(input.mtu || 1400); if (!Number.isInteger(mtu) || mtu < 1200 || mtu > 1460) throw new Error('MTU must be 1200–1460');
  const authMethod = input.authMethod || 'mschapv2'; if (!['mschapv2','pap','auto'].includes(authMethod)) throw new Error('Invalid PPP authentication method');
  const dns = Array.isArray(input.dns) ? input.dns : String(input.dns || '').split(/[\s,]+/).filter(Boolean);
  if (dns.length > 4 || dns.some(ip => net.isIP(ip) !== 4)) throw new Error('Specify up to four IPv4 VPN DNS servers');
  const prefixes = Array.isArray(input.allowedCidrs) ? input.allowedCidrs : String(input.allowedCidrs || '0.0.0.0/0').split(/[\s,]+/).filter(Boolean);
  if (!prefixes.length || prefixes.length > 100) throw new Error('Specify 1–100 allowed destination prefixes');
  const proposal = (value, fallback) => { value = value || fallback; if (typeof value !== 'string' || value.length > 512 || !/^[a-z0-9_+!, -]+$/i.test(value)) throw new Error('Invalid IPsec proposal'); return value.replace(/ /g, ''); };
  return { id, name: text(input.name, 'VPN name', 80), gateway: host(input.gateway), username: text(input.username, 'VPN username', 160), protocol, mtu, authMethod,
    dns, allowedCidrs: prefixes.map(cidr), remoteId: input.remoteId ? text(input.remoteId, 'remote IKE identity', 253) : '',
    ike: proposal(input.ike, 'aes256-sha256-modp2048!'), esp: proposal(input.esp, 'aes256-sha256!'), updatedAt: new Date().toISOString() };
}
function normalizeRule(input, id = crypto.randomUUID()) {
  if (!input || typeof input !== 'object') throw new Error('Routing rule required');
  const action = input.action || 'vpn'; if (!['vpn','direct','block'].includes(action)) throw new Error('Invalid route action');
  const priority = Number(input.priority ?? 100); if (!Number.isInteger(priority) || priority < 0 || priority > 100000) throw new Error('Rule priority must be 0–100000');
  const domain = input.domain ? text(input.domain, 'domain suffix', 253).toLowerCase().replace(/^\*\./, '').replace(/^\./, '') : '';
  if (domain && !/^[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?$/.test(domain)) throw new Error('Invalid domain suffix');
  const port = input.port ? Number(input.port) : 0; if (!Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Invalid rule port');
  return { id, name: text(input.name, 'rule name', 80), enabled: input.enabled !== false, action, priority,
    vpnId: action === 'vpn' ? text(input.vpnId, 'VPN profile', 80) : '', cidr: input.cidr ? cidr(input.cidr) : '', domain,
    group: input.group ? text(input.group, 'group', 60) : '', serverId: input.serverId ? text(input.serverId, 'server ID', 80) : '', port };
}
function publicVPN(value) { const { passwordSecret, pskSecret, ...safe } = value; return { ...safe, hasPassword: !!passwordSecret, hasPSK: !!pskSecret }; }
class NetworkConfig {
  constructor(store) { this.store = store; store.db.run('CREATE TABLE IF NOT EXISTS vpns (id TEXT PRIMARY KEY, data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS route_rules (id TEXT PRIMARY KEY, data TEXT NOT NULL);'); }
  vpns(internal = false) { return this.store.rows('SELECT data FROM vpns ORDER BY id').map(r => JSON.parse(r.data)).map(p => internal ? p : publicVPN(p)); }
  get(id) { const row = this.store.rows('SELECT data FROM vpns WHERE id=?', [id])[0]; if (!row) throw new Error('VPN profile no longer exists'); return JSON.parse(row.data); }
  rules() { return this.store.rows('SELECT data FROM route_rules ORDER BY id').map(r => JSON.parse(r.data)); }
  saveVPN(input, id) {
    const previous = id ? this.get(id) : null, value = normalizeVPN(input, id);
    if (previous?.shared) throw new Error('Shared VPNs are managed by their owner');
    for (const key of ['password', 'psk']) {
      const plain = input[key];
      if (plain !== undefined && typeof plain !== 'string') throw new Error('Invalid VPN credential');
      if (plain && (plain.length > 8192 || /[\r\n\0]/.test(plain))) throw new Error('VPN credentials cannot contain newlines or NUL');
      if (plain) { if (!this.store.vault.available()) throw new Error('OS credential vault unavailable'); value[key + 'Secret'] = this.store.vault.encrypt(plain); }
      else if (previous) value[key + 'Secret'] = previous[key + 'Secret'];
    }
    if (!value.passwordSecret) throw new Error('VPN password required');
    if (value.protocol === 'l2tp-ipsec-psk' && !value.pskSecret) throw new Error('IPsec PSK required');
    if (value.protocol === 'l2tp') delete value.pskSecret;
    this.store.db.run('INSERT OR REPLACE INTO vpns VALUES (?,?)', [value.id, JSON.stringify(value)]); this.store.audit('vpn.saved', value.name); return publicVPN(value);
  }
  removeVPN(id) {
    const value = this.get(id);
    if (value.shared) throw new Error('Remove the sharing server to remove managed VPNs');
    if (this.store.all().some(s => s.vpnId === id) || this.rules().some(r => r.vpnId === id)) throw new Error('VPN is referenced by connections or routing rules. Update those bindings first.');
    this.store.db.run('DELETE FROM vpns WHERE id=?', [id]); this.store.audit('vpn.removed', value.name);
  }
  saveRule(input, id) {
    if (id && !this.rules().some(r => r.id === id)) throw new Error('Routing rule no longer exists');
    const value = normalizeRule(input, id); if (value.vpnId && this.get(value.vpnId).shared) throw new Error('Shared VPNs cannot be used in local routing rules'); if (value.serverId && this.store.get(value.serverId).shared) throw new Error('Shared connections are managed by their owner');
    this.store.db.run('INSERT OR REPLACE INTO route_rules VALUES (?,?)', [value.id, JSON.stringify(value)]); this.store.audit('route.saved', value.name); return value;
  }
  removeRule(id) { this.store.db.run('DELETE FROM route_rules WHERE id=?', [id]); this.store.audit('route.removed', id); }
  duplicate(id) { const previous = this.get(id); if (previous.shared) throw new Error('Shared VPNs cannot be copied or exported'); const value = { ...previous, id: crypto.randomUUID(), name: previous.name.slice(0, 73) + ' (copy)', updatedAt: new Date().toISOString() }; this.store.db.run('INSERT INTO vpns VALUES (?,?)', [value.id, JSON.stringify(value)]); this.store.audit('vpn.copied', previous.name); return publicVPN(value); }
}
module.exports = { NetworkConfig, normalizeVPN, normalizeRule, publicVPN, cidr };
