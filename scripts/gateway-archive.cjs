const zlib = require('node:zlib');
function octal(data) { return parseInt(data.toString('ascii').replace(/\0.*$/, '').trim() || '0', 8); }
function tarEntries(buffer) {
  const result = []; let prefixName = '';
  for (let offset = 0; offset + 512 <= buffer.length;) {
    const h = buffer.subarray(offset, offset + 512); offset += 512;
    if (h.every(b => b === 0)) continue;
    const string = (start, end) => h.subarray(start, end).toString('utf8').replace(/\0.*$/, '');
    let name = string(0, 100), prefix = string(345, 500); if (prefix) name = prefix + '/' + name;
    const size = octal(h.subarray(124, 136)), mode = octal(h.subarray(100, 108)), type = string(156, 157), link = string(157, 257);
    const data = buffer.subarray(offset, offset + size); offset += Math.ceil(size / 512) * 512;
    if (type === 'L') { prefixName = data.toString('utf8').replace(/\0.*$/, ''); continue; }
    if (type === 'x' || type === 'g') continue;
    if (prefixName) { name = prefixName; prefixName = ''; }
    name = name.replace(/^\.\//, '').replace(/\/$/, '');
    if (!name || name.startsWith('/') || name.split('/').includes('..')) continue;
    result.push({ name, mode: mode | (type === '5' ? 0o040000 : type === '2' ? 0o120000 : 0o100000), data: type === '2' ? Buffer.from(link) : data, nlink: 1 });
  }
  return result;
}
function cpioEntries(buffer) {
  const result = [];
  for (let offset = 0; offset + 110 <= buffer.length;) {
    const h = buffer.subarray(offset, offset + 110); if (h.subarray(0, 6).toString() !== '070701') throw new Error('Expected newc initramfs');
    const field = index => parseInt(h.subarray(6 + index * 8, 14 + index * 8).toString(), 16);
    const namesize = field(11), size = field(6), name = buffer.subarray(offset + 110, offset + 110 + namesize - 1).toString();
    offset = Math.ceil((offset + 110 + namesize) / 4) * 4;
    const data = buffer.subarray(offset, offset + size); offset = Math.ceil((offset + size) / 4) * 4;
    if (name === 'TRAILER!!!') break;
    result.push({ name: name.replace(/^\.\//, ''), mode: field(1), nlink: field(4), data, rdevmajor: field(9), rdevminor: field(10) });
  }
  return result;
}
function cpio(entries) {
  const chunks = []; let inode = 1;
  const add = item => {
    const name = Buffer.from(item.name + '\0'), data = item.data || Buffer.alloc(0);
    const fields = [inode++, item.mode, 0, 0, 1, 0, data.length, 0, 0, item.rdevmajor || 0, item.rdevminor || 0, name.length, 0];
    const header = Buffer.from('070701' + fields.map(n => n.toString(16).padStart(8, '0')).join(''));
    chunks.push(header, name, Buffer.alloc((4 - (110 + name.length) % 4) % 4), data, Buffer.alloc((4 - data.length % 4) % 4));
  };
  const map = new Map(entries.filter(e => e.name && e.name !== '.').map(e => [e.name, e]));
  for (const name of [...map.keys()]) {
    const parts = name.split('/'); parts.pop();
    while (parts.length) { const directory = parts.join('/'); if (!map.has(directory)) map.set(directory, { name: directory, mode: 0o040755, data: Buffer.alloc(0) }); parts.pop(); }
  }
  [...map.values()].sort((a, b) => a.name.split('/').length - b.name.split('/').length || a.name.localeCompare(b.name)).forEach(add);
  add({ name: 'TRAILER!!!', mode: 0 }); return zlib.gzipSync(Buffer.concat(chunks), { level: 6 });
}
module.exports = { tarEntries, cpioEntries, cpio };
