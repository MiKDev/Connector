const crypto = require('node:crypto');
const net = require('node:net');

function text(value, name, max = 160) {
  if (typeof value !== 'string' || !value.trim() || value.length > max || /[\x00-\x1f\x7f]/.test(value)) throw new Error(`Invalid ${name}`);
  return value.trim();
}
function normalizeServer(input, id = crypto.randomUUID()) {
  if (!input || typeof input !== 'object') throw new Error('Server details required');
  const host = text(input.host, 'host', 253);
  if (!(net.isIP(host) || /^(?=.{1,253}$)[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(host))) throw new Error('Enter a hostname or IP address, without a URL or port');
  const port = input.port === undefined || input.port === '' ? 22 : Number(input.port);
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new Error('Port must be 1–65535');
  const auth = input.auth || 'agent';
  if (!['agent', 'key', 'password'].includes(auth)) throw new Error('Invalid authentication method');
  const routeMode = input.routeMode || 'direct';
  if (!['direct', 'vpn', 'auto'].includes(routeMode)) throw new Error('Invalid connection route');
  const vpnId = routeMode === 'vpn' ? text(input.vpnId, 'VPN profile', 80) : '';
  const keySource = input.keySource || 'file'; if (!['file','vault'].includes(keySource)) throw new Error('Invalid private key source');
  return { id, name: text(input.name, 'name', 80), host, port,
    username: text(input.username, 'username', 80), group: text(input.group || 'Ungrouped', 'group', 60),
    auth, routeMode, vpnId, ...(auth === 'key' ? { keySource } : {}), keyPath: auth === 'key' && keySource === 'file' ? text(input.keyPath, 'private key path', 1024) : '',
    updatedAt: new Date().toISOString() };
}
function validateCommand(command) {
  if (typeof command !== 'string' || !command.trim() || command.length > 16000 || command.includes('\0')) throw new Error('Command must contain 1–16000 characters without NUL');
  return command;
}
function snapshot(server) { return crypto.createHash('sha256').update(JSON.stringify(server)).digest('hex'); }
function publicServer(server) { const { secret, privateKeySecret, ...safe } = server; return { ...safe, hasSecret: !!secret, hasEmbeddedKey: !!privateKeySecret }; }
function timingEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const first = Buffer.from(a), second = Buffer.from(b);
  return first.length === second.length && crypto.timingSafeEqual(first, second);
}
module.exports = { normalizeServer, validateCommand, snapshot, publicServer, timingEqual, text };
