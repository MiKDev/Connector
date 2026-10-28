const net = require('node:net');
const ipaddr = require('ipaddr.js');
const { snapshot } = require('./core.cjs');
function address(value) { const a = ipaddr.parse(value); return a.kind() === 'ipv6' && a.isIPv4MappedAddress() ? a.toIPv4Address() : a; }
function matchesCIDR(host, prefix) { if (!net.isIP(host)) return false; const a = address(host), [b, bits] = ipaddr.parseCIDR(prefix); return a.kind() === b.kind() && a.match(b, bits); }
function routeFor(server, config) {
  const mode = server.routeMode || 'direct';
  if (mode === 'direct') return { action: 'direct', key: 'direct', name: 'Direct', fingerprint: 'direct' };
  let selected;
  if (mode === 'vpn') selected = { vpnId: server.vpnId, action: 'vpn', name: 'Explicit VPN binding' };
  else {
    const candidates = config.rules().filter(r => r.enabled && (!r.serverId || r.serverId === server.id) && (!r.group || r.group === server.group) && (!r.port || r.port === server.port) && (!r.cidr || matchesCIDR(server.host, r.cidr)) && (!r.domain || server.host.toLowerCase() === r.domain || server.host.toLowerCase().endsWith('.' + r.domain)))
      .map(r => ({ ...r, specificity: (r.serverId ? 100000 : 0) + (r.cidr ? Number(r.cidr.split('/')[1]) * 100 : 0) + (r.domain ? r.domain.length * 100 : 0) + (r.group ? 10 : 0) + (r.port ? 1 : 0) }))
      .sort((a, b) => a.priority - b.priority || b.specificity - a.specificity || a.id.localeCompare(b.id));
    if (!candidates.length) throw new Error('Automatic routing has no matching rule. Connection blocked; choose an explicit route.');
    selected = candidates[0];
    if (candidates.some(r => r.priority === selected.priority && r.specificity === selected.specificity && (r.action !== selected.action || r.vpnId !== selected.vpnId))) throw new Error('Ambiguous routing rules match this destination. Set a priority or bind a VPN explicitly.');
  }
  if (selected.action === 'block') throw new Error('Connection blocked by routing rule: ' + selected.name);
  if (selected.action === 'direct') return { action: 'direct', key: 'direct', name: selected.name, fingerprint: snapshot(selected) };
  const vpn = config.get(selected.vpnId);
  return { action: 'vpn', vpnId: vpn.id, key: 'vpn:' + vpn.id, name: vpn.name, fingerprint: snapshot({ vpn, rule: selected }) };
}
function socketReader(socket) {
  let buffered = Buffer.alloc(0), waiting = null, failure;
  const flush = () => { if (waiting && buffered.length >= waiting.length) { const { length, resolve } = waiting; waiting = null; const data = buffered.subarray(0, length); buffered = buffered.subarray(length); resolve(data); } };
  const onData = chunk => { buffered = Buffer.concat([buffered, chunk]); if (buffered.length > 65536) onError(new Error('Invalid proxy handshake')); else flush(); };
  const onError = error => { failure = error; if (waiting) { waiting.reject(error); waiting = null; } };
  const onClose = () => onError(new Error('Proxy closed the connection'));
  socket.on('data', onData); socket.on('error', onError); socket.on('close', onClose);
  return { read(length) { if (failure) return Promise.reject(failure); return new Promise((resolve, reject) => { waiting = { length, resolve, reject }; flush(); }); }, finish() {
    socket.pause(); socket.off('data', onData); socket.off('error', onError); socket.off('close', onClose); if (buffered.length) socket.unshift(buffered);
  } };
}
function tcp(host, port, signal) {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) { reject(new Error('Connection cancelled')); return; }
    const socket = net.createConnection({ host, port }), timer = setTimeout(() => socket.destroy(new Error('Connection timed out')), 20000);
    const abort = () => socket.destroy(new Error('Connection cancelled'));
    signal?.addEventListener('abort', abort, { once: true });
    const clean = () => { clearTimeout(timer); signal?.removeEventListener('abort', abort); };
    socket.once('error', error => { clean(); reject(error); }); socket.once('connect', () => { clean(); resolve(socket); });
  });
}
async function socksDial(proxy, host, port, signal) {
  const socket = await tcp('127.0.0.1', proxy.port, signal), reader = socketReader(socket);
  const abort = () => socket.destroy(new Error('Connection cancelled'));
  const timer = setTimeout(() => socket.destroy(new Error('VPN proxy handshake timed out')), 15000);
  signal?.addEventListener('abort', abort, { once: true });
  try {
    if (signal?.aborted) throw new Error('Connection cancelled');
    socket.write(Buffer.from([5, 1, 2])); const method = await reader.read(2);
    if (method[0] !== 5 || method[1] !== 2) throw new Error('VPN proxy authentication required');
    const user = Buffer.from(proxy.username), password = Buffer.from(proxy.password);
    if (!user.length || user.length > 255 || !password.length || password.length > 255) throw new Error('Invalid proxy credentials');
    socket.write(Buffer.concat([Buffer.from([1, user.length]), user, Buffer.from([password.length]), password]));
    const auth = await reader.read(2); if (auth[0] !== 1 || auth[1] !== 0) throw new Error('VPN proxy authentication failed');
    let target;
    if (net.isIP(host)) { const a = address(host); target = Buffer.concat([Buffer.from([a.kind() === 'ipv4' ? 1 : 4]), Buffer.from(a.toByteArray())]); }
    else { const domain = Buffer.from(host, 'ascii'); if (!domain.length || domain.length > 253) throw new Error('Invalid proxy destination'); target = Buffer.concat([Buffer.from([3, domain.length]), domain]); }
    const number = Buffer.alloc(2); number.writeUInt16BE(port);
    socket.write(Buffer.concat([Buffer.from([5, 1, 0]), target, number])); const reply = await reader.read(4);
    if (reply[0] !== 5 || reply[1] !== 0 || reply[2] !== 0) throw new Error('VPN could not reach destination (SOCKS ' + reply[1] + ')');
    const length = reply[3] === 1 ? 4 : reply[3] === 4 ? 16 : reply[3] === 3 ? (await reader.read(1))[0] : -1;
    if (length < 0) throw new Error('Invalid VPN proxy reply'); await reader.read(length + 2);
    reader.finish(); socket.setNoDelay(true); return socket;
  } catch (error) { socket.destroy(); throw error; }
  finally { clearTimeout(timer); signal?.removeEventListener('abort', abort); }
}
class Routes {
  constructor(config, gateways) { this.config = config; this.gateways = gateways; this.sockets = new Set(); }
  select(server) { return routeFor(server, this.config); }
  fingerprint(server) { return this.select(server).fingerprint; }
  async dial(server, signal) {
    const route = this.select(server);
    let socket;
    if (route.action === 'vpn') { const proxy = await this.gateways.ensure(route.vpnId, signal); socket = await socksDial(proxy, server.host, server.port, signal); this.gateways.track(route.vpnId, socket); }
    else socket = await tcp(server.host, server.port, signal);
    if (route.fingerprint !== this.fingerprint(server) || signal?.aborted) { socket.destroy(); throw new Error('Route changed or connection cancelled during setup'); }
    const entry = { socket, serverId: server.id, route }; this.sockets.add(entry); socket.once('close', () => this.sockets.delete(entry));
    return { socket, ...route };
  }
  invalidate(serverId) { for (const entry of this.sockets) if (!serverId || entry.serverId === serverId) entry.socket.destroy(); }
  shutdown() { this.invalidate(); this.gateways.shutdown(); }
}
module.exports = { Routes, routeFor, matchesCIDR, socksDial, tcp };
