const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { Files, cleanPath, basename } = require('../electron/files.cjs');
const { Store } = require('../electron/store.cjs');
const { SSH } = require('../electron/ssh.cjs');
const { startServer } = require('./ssh-fixture.cjs');
const vault = { available: () => true, encrypt: s => Buffer.from(s).toString('base64'), decrypt: s => Buffer.from(s, 'base64').toString() };
async function setup(t, options = {}) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'connector-files-'));
  const local = path.join(directory, 'local'), source = path.join(directory, 'source'), destination = path.join(directory, 'destination');
  [local, source, destination].forEach(d => fs.mkdirSync(d));
  const a = await startServer(undefined, { root: source, directExec: options.directExec ?? process.platform === 'linux' });
  const b = await startServer(undefined, { root: destination });
  const store = await Store.open(path.join(directory, 'data'), vault);
  const add = (name, port) => store.put({ name, host: '127.0.0.1', port, username: 'tester', auth: 'password', secret: 'test-password' });
  const sourceServer = add('Source', a.port), destinationServer = add('Destination', b.port);
  const ssh = new SSH(store, vault, async () => true, () => {});
  const files = new Files(store, ssh, vault, () => {});
  t.after(async () => { files.shutdown(); ssh.closeAll(); await a.close(); await b.close(); store.db.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  const sourceEndpoint = await files.open(sourceServer.id), destinationEndpoint = await files.open(destinationServer.id);
  return { files, directory, local, source, destination, sourceEndpoint, destinationEndpoint, store, sourceServer, ssh };
}
async function finish(files, id) { const deadline=Date.now()+30000; while(Date.now()<deadline) { const job = files.jobs.get(id); if (job.status !== 'running') return files.view(job); await new Promise(r => setTimeout(r, 20)); } throw new Error('Transfer did not finish: '+JSON.stringify(files.view(files.jobs.get(id)))); }
const hash = filename => crypto.createHash('sha256').update(fs.readFileSync(filename)).digest('hex');
test('file name and absolute path validation refuses traversal and control characters', () => {
  for (const name of ['..', '.', '../x', 'a/b', 'a\\b', 'a\0b']) assert.throws(() => basename(name));
  assert.throws(() => cleanPath('relative/path', false)); assert.throws(() => cleanPath('/tmp/x\ny', false));
  assert.equal(basename('file name فارسی.txt'), 'file name فارسی.txt');
});
test('real SFTP upload/download supports binary data, trees, exclusive destination and saved-credential reuse', async t => {
  const { files, local, destination, destinationEndpoint, store, sourceServer, sourceEndpoint } = await setup(t);
  const tree = path.join(local, 'nested'); fs.mkdirSync(tree); fs.mkdirSync(path.join(tree, 'empty'));
  fs.writeFileSync(path.join(tree, 'file name فارسی.bin'), crypto.randomBytes(180000));
  const input = { source: { endpointId: 'local', path: local, names: ['nested'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } };
  const plan = await files.prepare(input); assert.equal(plan.route, 'device'); assert.equal(plan.files.length, 1);
  const job = await finish(files, files.start(plan).id); assert.equal(job.status, 'completed', job.error);
  assert.equal(hash(path.join(tree, 'file name فارسی.bin')), hash(path.join(destination, 'nested', 'file name فارسی.bin')));
  assert.ok(fs.statSync(path.join(destination, 'nested', 'empty')).isDirectory());
  await assert.rejects(() => files.prepare(input), /already exists/);
  const download = path.join(local, 'download'); fs.mkdirSync(download);
  const backwards = await files.prepare({ source: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home, names: ['nested'] }, destination: { endpointId: 'local', path: download } });
  assert.equal((await finish(files, files.start(backwards).id)).status, 'completed');
  assert.equal(hash(path.join(tree, 'file name فارسی.bin')), hash(path.join(download, 'nested', 'file name فارسی.bin')));
  const listing = await files.listing(destinationEndpoint.id, destinationEndpoint.home); assert.ok(listing.entries.some(e => e.name === 'nested' && e.kind === 'folder'));
  assert.equal((await files.open(sourceServer.id)).id, sourceEndpoint.id, 'SFTP connections reuse saved profiles and cached endpoint');
  store.put({ ...store.get(sourceServer.id), name: 'Changed', secret: '' }, sourceServer.id);
  assert.throws(() => files.endpoint(sourceEndpoint.id), /profile.*changed/);
});
test('SFTP cancellation removes incomplete files without touching completed or existing data', async t => {
  const { files, local, destination, destinationEndpoint } = await setup(t);
  fs.writeFileSync(path.join(local, 'cancel.bin'), crypto.randomBytes(4 * 1024 * 1024));
  const plan = await files.prepare({ source: { endpointId: 'local', path: local, names: ['cancel.bin'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } });
  const view = files.start(plan); files.cancel(view.id);
  const job = await finish(files, view.id); assert.equal(job.status, 'cancelled'); assert.equal(fs.existsSync(path.join(destination, 'cancel.bin')), false);
  fs.writeFileSync(path.join(destination, 'cancel.bin'), 'original');
  await assert.rejects(() => files.prepare({ source: { endpointId: 'local', path: local, names: ['cancel.bin'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } }), /already exists/);
  assert.equal(fs.readFileSync(path.join(destination, 'cancel.bin'), 'utf8'), 'original');
});
test('multi-connect starts connections concurrently, reports each result and isolates failures', async () => {
  const ssh = new SSH({ get: id => ({ id }) }, {}, () => {}, () => {});
  let active = 0, maximum = 0; const events = [];
  ssh.open = async id => { active++; maximum = Math.max(maximum, active); await new Promise(r => setTimeout(r, 15)); active--; if (id === 'bad') throw new Error('test failure'); return { sessionId: id, serverId: id }; };
  const results = await ssh.openMany(['a', 'b', 'bad', 'd', 'e'], r => events.push(r));
  assert.equal(maximum, 4); assert.equal(events.length, 5); assert.equal(results.filter(r => r.session).length, 4); assert.equal(results[2].error, 'test failure');
  await assert.rejects(() => ssh.openMany(['a', 'a']), /distinct/);
});
test('a source without direct-transfer support fails without desktop relay or credential disclosure and cleans reservations', async t => {
  const { files, source, destination, sourceEndpoint, destinationEndpoint } = await setup(t, { directExec: false });
  fs.writeFileSync(path.join(source, 'not-relayed.bin'), crypto.randomBytes(1000));
  const plan = await files.prepare({ source: { endpointId: sourceEndpoint.id, path: sourceEndpoint.home, names: ['not-relayed.bin'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } });
  plan.from.sftp.createReadStream = () => { throw new Error('Must not fall back to desktop relay'); };
  const job = await finish(files, files.start(plan).id);
  assert.equal(job.status, 'failed'); assert.equal(fs.existsSync(path.join(destination, 'not-relayed.bin')), false);
  assert.equal(JSON.stringify(job).includes('test-password'), false);
});
test('direct transfer runs source OpenSSH SFTP against destination; no file stream crosses the desktop', { skip: process.platform !== 'linux' }, async t => {
  const { files, source, destination, sourceEndpoint, destinationEndpoint } = await setup(t);
  fs.writeFileSync(path.join(source, 'direct file فارسی.bin'), crypto.randomBytes(300000));
  const plan = await files.prepare({ source: { endpointId: sourceEndpoint.id, path: sourceEndpoint.home, names: ['direct file فارسی.bin'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } });
  assert.equal(plan.route, 'direct');
  // Fail if the app attempts to read file content over its own SFTP channels.
  plan.from.sftp.createReadStream = () => { throw new Error('Desktop must not read direct-transfer content'); };
  plan.to.sftp.createWriteStream = () => { throw new Error('Desktop must not relay direct-transfer content'); };
  const commands = [], originalConnect = files.ssh.connect.bind(files.ssh);
  files.ssh.connect = async (...args) => { const client = await originalConnect(...args); const exec = client.exec.bind(client); client.exec = (command, ...rest) => { commands.push(command); return exec(command, ...rest); }; return client; };
  const job = await finish(files, files.start(plan).id);
  assert.equal(job.status, 'completed', job.error);
  assert.equal(hash(path.join(source, 'direct file فارسی.bin')), hash(path.join(destination, 'direct file فارسی.bin')));
  assert.equal(job.bytes, 300000);
  assert.ok(commands.length > 0); assert.ok(commands.every(command => !command.includes('test-password')), 'borrowed credential is never a process command argument');
});
test('direct cancellation revokes the remote operation and cleans reserved destination files', { skip: process.platform !== 'linux' }, async t => {
  const { files, source, destination, sourceEndpoint, destinationEndpoint } = await setup(t);
  fs.writeFileSync(path.join(source, 'cancel-direct.bin'), crypto.randomBytes(3 * 1024 * 1024));
  const plan = await files.prepare({ source: { endpointId: sourceEndpoint.id, path: sourceEndpoint.home, names: ['cancel-direct.bin'] }, destination: { endpointId: destinationEndpoint.id, path: destinationEndpoint.home } });
  let revoked = false;
  files.emit = (_type, event) => { if (event.route === 'direct' && event.current && !revoked) { revoked = true; files.cancel(event.id); } };
  const job = await finish(files, files.start(plan).id);
  assert.equal(job.status, 'cancelled', job.error); assert.equal(revoked, true);
  assert.equal(fs.existsSync(path.join(destination, 'cancel-direct.bin')), false);
});
