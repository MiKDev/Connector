const known = new Set(['ubuntu','debian','fedora','rhel','centos','rocky','almalinux','alpine','arch','manjaro','opensuse','sles','gentoo','nixos','kali','linuxmint','amzn','ol']);
function parseDistro(output) {
  if (typeof output !== 'string' || output.length > 16384) return null;
  const field = name => { const match = output.match(new RegExp('^' + name + '=(.*)$', 'm')); return match ? match[1].trim().replace(/^["']|["']$/g, '').toLowerCase() : ''; };
  for (let id of [field('ID'), ...field('ID_LIKE').split(/\s+/)]) { if (id.startsWith('opensuse')) id = 'opensuse'; if (known.has(id)) return id; }
  if (/^Darwin\s*$/i.test(output)) return 'macos';
  if (/^Linux\s*$/i.test(output) || field('ID')) return 'linux';
  return null;
}
module.exports = { parseDistro };
