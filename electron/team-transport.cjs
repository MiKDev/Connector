const tls = require('node:tls');
const crypto = require('node:crypto');
const { StringDecoder } = require('node:string_decoder');
const { timingEqual } = require('./core.cjs');
const MAX = 4 * 1024 * 1024;
// Minimal DER certificate construction; all cryptography and TLS are supplied
// by Node/OpenSSL, with the exact certificate pinned in the invitation.
function der(tag, ...parts) {
  const body = Buffer.concat(parts.map(p => Buffer.isBuffer(p) ? p : Buffer.from(p)));
  const bytes = []; let n = body.length; do { bytes.unshift(n & 255); n >>>= 8; } while (n);
  return Buffer.concat([Buffer.from([tag, ...(body.length < 128 ? [body.length] : [128 + bytes.length, ...bytes])]), body]);
}
function identity() {
  const pair = crypto.generateKeyPairSync('rsa', { modulusLength: 2048 });
  const alg = Buffer.from('300d06092a864886f70d01010b0500', 'hex');
  const name = der(0x30, der(0x31, der(0x30, Buffer.from('0603550403', 'hex'), der(0x0c, 'Connector sharing'))));
  const serial = crypto.randomBytes(16); serial[0] &= 0x7f; serial[0] |= 1;
  const time = d => der(0x17, d.toISOString().replace(/[-:]/g, '').slice(2, 15).replace('T', '') + 'Z');
  const tbs = der(0x30, der(0x02, serial), alg, name, der(0x30, time(new Date(Date.now() - 86400000)), time(new Date(Date.now() + 10 * 365 * 86400000))), name, pair.publicKey.export({ type: 'spki', format: 'der' }));
  const cert = der(0x30, tbs, alg, der(0x03, Buffer.from([0]), crypto.sign('sha256', tbs, pair.privateKey)));
  const pem = '-----BEGIN CERTIFICATE-----\n' + cert.toString('base64').match(/.{1,64}/g).join('\n') + '\n-----END CERTIFICATE-----\n';
  const x509 = new crypto.X509Certificate(pem);
  if (!x509.verify(pair.publicKey)) throw new Error('Certificate verification failed');
  return { cert: pem, key: pair.privateKey.export({ type: 'pkcs8', format: 'pem' }), fingerprint: crypto.createHash('sha256').update(cert).digest('hex') };
}
function channel(socket, receive) {
  let text = '', bytes = 0; const decoder = new StringDecoder('utf8');
  socket.on('error', () => {}); socket.setNoDelay(true);
  socket.on('data', chunk => {
    bytes += chunk.length;
    if (bytes > MAX) { socket.destroy(); return; }
    text += decoder.write(chunk);
    let end;
    while ((end = text.indexOf('\n')) >= 0) {
      const line = text.slice(0, end); text = text.slice(end + 1); bytes = Buffer.byteLength(text);
      try { const message = JSON.parse(line); if (!message || typeof message !== 'object' || Array.isArray(message)) throw new Error(); receive(message); } catch { socket.destroy(); return; }
    }
  });
  return message => {
    if (socket.destroyed) return false;
    const data = JSON.stringify(message) + '\n';
    if (Buffer.byteLength(data) > MAX || socket.writableLength > MAX) { socket.destroy(); return false; }
    socket.write(data); return true;
  };
}
function connect(invite) {
  const socket = tls.connect({ host: invite.host, port: invite.port, rejectUnauthorized: false, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3' });
  // No application data (including bearer credentials) is sent until the exact
  // invitation fingerprint is checked. A public CA/hostname is not the identity.
  const ready = new Promise((resolve, reject) => {
    const timer = setTimeout(() => socket.destroy(new Error('Sharing connection timed out')), 10000);
    socket.once('error', reject);
    socket.once('close', () => { clearTimeout(timer); reject(new Error('Sharing server disconnected')); });
    socket.once('secureConnect', () => {
      const cert = socket.getPeerCertificate().raw;
      if (!cert || !timingEqual(crypto.createHash('sha256').update(cert).digest('hex'), invite.fingerprint)) { socket.destroy(new Error('Sharing server identity does not match the invitation')); return; }
      clearTimeout(timer); resolve(socket);
    });
  });
  return { socket, ready };
}
module.exports = { identity, channel, connect, MAX };
