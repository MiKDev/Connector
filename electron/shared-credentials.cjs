const fs = require('node:fs');
const { utils } = require('ssh2');
const crypto = require('node:crypto');
const MAX_KEY = 128 * 1024;
function validatePrivateKey(value, passphrase) {
  if (typeof value !== 'string' || !value || Buffer.byteLength(value) > MAX_KEY) throw new Error('Private key must be at most 128 KiB');
  const parsed = utils.parseKey(value, passphrase || undefined);
  if (parsed instanceof Error || !parsed || (Array.isArray(parsed) ? parsed.some(k => !k.isPrivateKey()) : !parsed.isPrivateKey())) throw new Error('Private key cannot be read with its saved passphrase');
  return value;
}
function readPrivateKey(profile, vault) {
  let value;
  if (profile.keySource === 'vault') { if (!profile.privateKeySecret) throw new Error('Shared private key material was not delivered'); value = vault.decrypt(profile.privateKeySecret); }
  else { const stat = fs.statSync(profile.keyPath); if (!stat.isFile() || stat.size > MAX_KEY) throw new Error('Private key file must be at most 128 KiB'); value = fs.readFileSync(profile.keyPath, 'utf8'); }
  return validatePrivateKey(value, profile.secret ? vault.decrypt(profile.secret) : '');
}
function keyFileFingerprint(profile) { if(profile.auth!=='key'||profile.keySource==='vault')return undefined;try{const stat=fs.statSync(profile.keyPath);if(!stat.isFile()||stat.size>MAX_KEY)return 'unavailable';return crypto.createHash('sha256').update(fs.readFileSync(profile.keyPath)).digest('hex');}catch{return 'unavailable';} }
module.exports = { readPrivateKey, validatePrivateKey, keyFileFingerprint, MAX_KEY };
