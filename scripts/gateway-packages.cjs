const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const { buffer, download, digest } = require('./gateway-download.cjs');
const { tarEntries } = require('./gateway-archive.cjs');
async function packages() {
  const cache = path.resolve('runtime-cache'), repository = 'https://dl-cdn.alpinelinux.org/alpine/v3.24/main/x86_64/';
  const indexPath = path.join(cache, 'APKINDEX-main.tar.gz');
  if (!fs.existsSync(indexPath)) fs.writeFileSync(indexPath, await buffer(repository + 'APKINDEX.tar.gz'));
  const index = tarEntries(zlib.gunzipSync(fs.readFileSync(indexPath))).find(e => e.name === 'APKINDEX');
  if (!index) throw new Error('APK index missing');
  const records = index.data.toString().split('\n\n').filter(Boolean).map(block => Object.fromEntries(block.split('\n').filter(line => line[1] === ':').map(line => [line[0], line.slice(2)])));
  const names = new Map(records.map(p => [p.P, p])), providers = new Map();
  for (const pkg of records) for (const name of (pkg.p || '').split(' ')) if (name && (!providers.has(name.split('=')[0]) || pkg.P === 'busybox-binsh')) providers.set(name.split('=')[0], pkg);
  const selected = new Map();
  const add = name => {
    if (!name || name.startsWith('!')) return;
    name = name.replace(/[<>=~].*$/, '');
    const pkg = names.get(name) || providers.get(name);
    if (!pkg) throw new Error('Missing Alpine dependency: ' + name);
    if (selected.has(pkg.P)) return; selected.set(pkg.P, pkg);
    for (const dependency of (pkg.D || '').split(' ')) add(dependency);
  };
  for (const name of ['strongswan', 'xl2tpd', 'ppp-daemon', 'ppp-l2tp', 'python3', 'iproute2-minimal', 'iptables', 'kmod']) add(name);
  const list = [...selected.values()]; let cursor = 0;
  await Promise.all(Array.from({ length: 8 }, async () => {
    while (cursor < list.length) {
      const pkg = list[cursor++], filename = `${pkg.P}-${pkg.V}.apk`;
      await download(repository + filename, path.join(cache, 'apks', filename));
      console.log('Gateway package:', filename);
    }
  }));
  const manifest = [];
  for (const pkg of list) { const filename = `${pkg.P}-${pkg.V}.apk`; manifest.push({ name: pkg.P, version: pkg.V, filename, license: pkg.L, source: pkg.U, sha256: await digest(path.join(cache, 'apks', filename)) }); }
  fs.writeFileSync(path.join(cache, 'packages.json'), JSON.stringify({ repository, verification: 'APK package signatures are enforced by apk inside the gateway before service startup', packages: manifest }, null, 2));
  console.log('Gateway dependency closure:', manifest.length, 'packages');
}
module.exports = { packages };
if (require.main === module) packages().catch(error => { console.error(error.message); process.exitCode = 1; });
