const { BaseAgent, createAgent, utils } = require('ssh2');
function publicBlob(key) {
  if (key && typeof key.getPublicSSH === 'function') return key.getPublicSSH();
  const parsed = utils.parseKey(key); if (!parsed || parsed instanceof Error || Array.isArray(parsed)) throw new Error('Invalid SSH agent identity'); return parsed.getPublicSSH();
}
function nativeAgent() {
  const path = process.env.SSH_AUTH_SOCK || (process.platform === 'win32' ? '\\\\.\\pipe\\openssh-ssh-agent' : '');
  if (!path) throw new Error('Server SSH agent is unavailable'); return createAgent(path);
}
// Accept only SSH public-key user authentication for the shared username.
// This is not a generic signing endpoint (no hostbased, certificates, or data).
function validateAuthentication(data, publicKey, username) {
  if (!Buffer.isBuffer(data) || data.length > 65536) throw new Error('Invalid agent authentication data');
  let offset = 0;
  const string = () => { if (offset + 4 > data.length) throw new Error('Invalid SSH string'); const n=data.readUInt32BE(offset);offset+=4;if(n>65536||offset+n>data.length)throw new Error('Invalid SSH string');const v=data.subarray(offset,offset+n);offset+=n;return v; };
  const session = string(); if (![20,32,48,64].includes(session.length) || data[offset++] !== 50 || string().toString() !== username || string().toString() !== 'ssh-connection' || string().toString() !== 'publickey' || data[offset++] !== 1) throw new Error('Agent request is not authorized SSH user authentication');
  const algorithm=string().toString(),blob=string();
  if (!/^(ssh-ed25519|ssh-rsa|rsa-sha2-256|rsa-sha2-512|ecdsa-sha2-nistp(?:256|384|521))$/.test(algorithm) || !blob.equals(publicKey) || offset !== data.length) throw new Error('Invalid SSH authentication key');
}
class SharedAgent extends BaseAgent {
  constructor(request) { super(); this.request = request; }
  getIdentities(callback) { this.request({ operation:'identities' }).then(value=>{
    if (!Array.isArray(value.keys) || value.keys.length>64) throw new Error('Invalid shared agent identities');
    const keys=value.keys.map(key=>utils.parseKey(Buffer.from(key,'base64'))); if(keys.some(k=>!k||k instanceof Error||Array.isArray(k)))throw new Error('Invalid shared agent identity');callback(null,keys);
  }).catch(callback); }
  sign(key,data,options,callback) { if(typeof options==='function'){callback=options;options={};} let blob;try{blob=publicBlob(key);}catch(e){callback(e);return;}
    this.request({operation:'sign',publicKey:blob.toString('base64'),data:data.toString('base64'),hash:options?.hash||''}).then(value=>{if(typeof value.signature!=='string'||value.signature.length>32768)throw new Error('Invalid agent signature');callback(null,Buffer.from(value.signature,'base64'));}).catch(callback);
  }
}
module.exports = { SharedAgent, nativeAgent, publicBlob, validateAuthentication };
