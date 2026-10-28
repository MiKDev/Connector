const fs = require('node:fs');
const path = require('node:path');
const https = require('node:https');
const crypto = require('node:crypto');
const { execFile } = require('node:child_process');
const { promisify } = require('node:util');
const run = promisify(execFile);
function request(url, method = 'GET', redirects = 0) {
  return new Promise((resolve, reject) => {
    if (!url.startsWith('https://') || redirects > 8) { reject(new Error('Invalid HTTPS download redirect')); return; }
    const req = https.request(url, { method }, response => {
      if (response.statusCode >= 300 && response.statusCode < 400 && response.headers.location) { response.resume(); resolve(request(new URL(response.headers.location, url).href, method, redirects + 1)); }
      else if (response.statusCode !== 200) { response.resume(); reject(new Error(`HTTP ${response.statusCode}: ${url}`)); }
      else resolve({ response, url });
    });
    req.on('error', reject); req.setTimeout(30000, () => req.destroy(new Error('HTTPS download timed out'))); req.end();
  });
}
async function buffer(url) { const { response } = await request(url); const chunks = []; for await (const b of response) chunks.push(b); return Buffer.concat(chunks); }
async function digest(file, algorithm = 'sha256') { const hash = crypto.createHash(algorithm); for await (const b of fs.createReadStream(file)) hash.update(b); return hash.digest('hex'); }
async function download(url, filename, expected, algorithm = 'sha256') {
  fs.mkdirSync(path.dirname(filename), { recursive: true });
  if (fs.existsSync(filename) && (!expected || await digest(filename, algorithm) === expected)) return filename;
  const { response, url: finalURL } = await request(url, 'HEAD'); response.resume();
  const size = Number(response.headers['content-length']);
  if (size > 4 * 1024 * 1024 && response.headers['accept-ranges'] === 'bytes') {
    const folder = filename + '.chunks'; fs.mkdirSync(folder, { recursive: true });
    const chunk = 2 * 1024 * 1024, count = Math.ceil(size / chunk); let cursor = 0, done = 0;
    await Promise.all(Array.from({ length: 12 }, async () => {
      while (cursor < count) {
        const i = cursor++, start = i * chunk, end = Math.min(size - 1, start + chunk - 1), part = path.join(folder, String(i));
        if (!fs.existsSync(part) || fs.statSync(part).size !== end - start + 1) {
          const result = await run(process.platform === 'win32' ? 'curl.exe' : 'curl', ['--fail','--location','--silent','--show-error','--max-time','180','--retry','2','--range',`${start}-${end}`,finalURL,'-o',part,'-w','%{http_code}'], { windowsHide: true, maxBuffer: 1024 * 1024 });
          if (result.stdout.trim() !== '206' || fs.statSync(part).size !== end - start + 1) throw new Error('Invalid download range');
        }
        done++; if (done % 16 === 0 || done === count) console.log(path.basename(filename) + `: ${done}/${count} parts`);
      }
    }));
    const fd = fs.openSync(filename, 'w'); try { for (let i = 0; i < count; i++) fs.writeSync(fd, fs.readFileSync(path.join(folder, String(i)))); } finally { fs.closeSync(fd); }
  } else {
    const { response: stream } = await request(url); const output = fs.createWriteStream(filename + '.partial');
    await require('node:stream/promises').pipeline(stream, output); fs.renameSync(filename + '.partial', filename);
  }
  if (expected && await digest(filename, algorithm) !== expected) throw new Error('Checksum mismatch: ' + path.basename(filename));
  return filename;
}
module.exports = { buffer, download, digest };
if (require.main === module) (async () => {
  const cache = path.resolve('runtime-cache');
  const qemu = 'qemu-w64-setup-20260811';
  const sha = (await buffer('https://qemu.weilnetz.de/w64/' + qemu + '.sha512')).toString().match(/[a-fA-F0-9]{128}/)[0].toLowerCase();
  const base = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/releases/x86_64/';
  const iso = 'alpine-virt-3.24.3-x86_64.iso', root = 'alpine-minirootfs-3.24.3-x86_64.tar.gz';
  await Promise.all([
    ...(process.platform === 'win32' ? [download('https://qemu.weilnetz.de/w64/' + qemu + '.exe', path.join(cache, qemu + '.exe'), sha, 'sha512')] : []),
    ...[iso, root].map(async name => { const sum = (await buffer(base + name + '.sha256')).toString().match(/[a-fA-F0-9]{64}/)[0].toLowerCase(); await download(base + name, path.join(cache, name), sum); })
  ]);
  fs.writeFileSync(path.join(cache, 'downloads-verified.json'), JSON.stringify({ qemu: qemu + '.exe', iso, root, fetchedFrom: ['https://qemu.weilnetz.de/w64/', base] }, null, 2));
  console.log('QEMU and Alpine downloads verified.');
})().catch(error => { console.error(error.message); process.exitCode = 1; });
