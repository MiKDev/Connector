const { test } = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { normalizeServer, validateCommand, timingEqual } = require('../electron/core.cjs');
const { Store } = require('../electron/store.cjs');
const { Service } = require('../electron/service.cjs');
const { createHandler, startBroker, callBroker } = require('../electron/mcp.cjs');
const fixture = { name: 'Test', host: '127.0.0.1', username: 'tester', group: 'Tests', auth: 'agent' };
async function setup(t, vault = { available: () => false }) {
  const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'connector-core-'));
  const store = await Store.open(directory, vault);
  t.after(() => { store.db.close(); fs.rmSync(directory, { recursive: true, force: true }); });
  return { directory, store };
}
test('validates host, authentication, port and shell command boundaries', () => {
  assert.equal(normalizeServer(fixture).port, 22);
  for (const host of ['https://example.com', 'example.com;whoami', 'x\ny', '-oProxyCommand=x']) assert.throws(() => normalizeServer({ ...fixture, host }));
  for (const port of [0, 65536, 1.5, 'x']) assert.throws(() => normalizeServer({ ...fixture, port }));
  assert.throws(() => normalizeServer({ ...fixture, auth: 'unknown' }));
  assert.throws(() => validateCommand('echo x\0rm'));
  assert.equal(validateCommand('uname -a\nuptime'), 'uname -a\nuptime');
  assert.equal(timingEqual('a', 'a'), true); assert.equal(timingEqual('a', 'bb'), false);
  assert.equal(timingEqual('é', 'a'), false);
});
test('SQLite persists profiles and pins, refuses plaintext credential fallback', async t => {
  const { directory, store } = await setup(t);
  const s = store.put(fixture);
  assert.throws(() => store.put({ ...fixture, auth: 'password', secret: 'never-save-me' }), /Secure OS/);
  assert.ok(!fs.readFileSync(store.filename).includes(Buffer.from('never-save-me')));
  store.pin('[127.0.0.1]:22', 'SHA256:test');
  const reopened = await Store.open(directory, { available: () => false });
  assert.equal(reopened.get(s.id).name, 'Test'); assert.equal(reopened.fingerprint('[127.0.0.1]:22'), 'SHA256:test'); reopened.db.close();
});
test('MCP mutations require desktop approval and changed targets invalidate execution', async t => {
  const { store } = await setup(t);
  const server = store.put(fixture);
  let executions = 0;
  const service = new Service(store, { exec: async () => { executions++; return { status: 'succeeded', exitCode: 0 }; } }, () => {});
  const handle = createHandler(service);
  const call = (name, args) => handle({ jsonrpc: '2.0', id: 1, method: 'tools/call', params: { name, arguments: args } });
  await assert.rejects(() => call('list_servers', {}), /Enable AI/);
  service.setAI(true);
  const add = await call('request_add_server', { ...fixture, auth: 'password' }); assert.equal(add.result.isError, true);
  const response = await call('request_add_server', { name: 'New', host: 'localhost', username: 'tester' });
  const req = JSON.parse(response.result.content[0].text);
  assert.equal(store.all().length, 1); await service.decide(req.id, true); assert.equal(store.all().length, 2);
  const plan = service.request('execution', { command: 'uptime', serverIds: [server.id] });
  assert.equal(executions, 0);
  store.put({ ...fixture, host: 'other.example' }, server.id);
  await assert.rejects(() => service.decide(plan.id, true), /target.*changed/); assert.equal(executions, 0);
  const remove = service.request('remove', { serverId: server.id });
  await service.decide(remove.id, false); assert.equal(store.all().length, 2);
  const edit = service.request('update', { serverId: server.id, changes: { group: 'Updated' } });
  assert.notEqual(store.get(server.id).group, 'Updated'); await service.decide(edit.id, true); assert.equal(store.get(server.id).group, 'Updated');
  const credentialServer = store.put({ ...fixture, auth: 'key', keyPath: 'test-key-reference' });
  assert.throws(() => service.request('update', { serverId: credentialServer.id, changes: { host: 'other.example' } }), /protect credentials/);
  const expired = service.request('remove', { serverId: server.id }); expired.expiresAt = new Date(0).toISOString();
  await assert.rejects(() => service.decide(expired.id, true), /expired/);
  const pending = service.request('remove', { serverId: server.id }); service.setAI(false);
  assert.equal(pending.status, 'rejected');
});
test('batches limit concurrency, isolate results and cancel queued targets', async t => {
  const { store } = await setup(t);
  const ids = Array.from({ length: 6 }, (_, i) => store.put({ ...fixture, name: `Server ${i}` }).id);
  let active = 0, maximum = 0;
  const service = new Service(store, { exec: async (_s, _c, _t, signal, output) => {
    active++; maximum = Math.max(active, maximum); output('sample', false);
    await new Promise(resolve => setTimeout(resolve, 25)); active--;
    return { status: signal.aborted ? 'cancelled' : 'succeeded', exitCode: 0 };
  } }, () => {});
  const job = service.run({ serverIds: ids, command: 'uptime' });
  assert.throws(() => service.run({ serverIds: ids, command: 'uptime' }), /Another batch/);
  while (service.jobs.get(job.id).status === 'running') await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(maximum, 4); assert.equal(service.jobs.get(job.id).results.every(r => r.stdout === 'sample' && r.status === 'succeeded'), true);
  const cancelled = service.run({ serverIds: ids, command: 'uptime' }); service.cancel(cancelled.id);
  while (service.jobs.get(cancelled.id).status === 'running') await new Promise(resolve => setTimeout(resolve, 10));
  assert.equal(service.jobs.get(cancelled.id).results.every(r => r.status === 'cancelled'), true);
});
test('authenticated local broker refuses invalid token and disables tools when AI is off', async t => {
  const { directory, store } = await setup(t);
  const service = new Service(store, {}, () => {});
  const broker = await startBroker(directory, service); t.after(() => broker.close());
  const descriptor = JSON.parse(fs.readFileSync(broker.descriptorPath, 'utf8'));
  const init = await callBroker(descriptor, { jsonrpc: '2.0', id: 7, method: 'initialize' });
  assert.equal(init.result.serverInfo.name, 'connector');
  await assert.rejects(() => callBroker({ ...descriptor, token: 'wrong' }, { jsonrpc: '2.0', id: 8, method: 'tools/list' }));
  const blocked = await callBroker(descriptor, { jsonrpc: '2.0', id: 9, method: 'tools/list' }); assert.ok(blocked.error);
  service.setAI(true);
  const result = await callBroker(descriptor, { jsonrpc: '2.0', id: 10, method: 'tools/list' }); assert.equal(result.result.tools.length, 7);
});

test('individual cancellation and removal leave other interactive and queued targets independent', async t => {
  const { store } = await setup(t);
  const ids = Array.from({ length: 6 }, (_, i) => store.put({ ...fixture, name: `Interactive ${i}` }).id);
  const started = [], written = [];
  const ssh = { exec: (_server, _command, _timeout, signal, output, options) => new Promise(resolve => {
    started.push(_server.id);
    const finish = status => resolve({ status, exitCode: status === 'succeeded' ? 0 : null });
    signal.addEventListener('abort', () => finish('cancelled'), { once: true });
    options.onReady({ write: data => { written.push([_server.id, data]); output('Confirmed', false); finish('succeeded'); }, resize: () => {} });
    output('Continue? [y/N]', false);
  }) };
  const service = new Service(store, ssh, () => {});
  const view = service.run({ serverIds: ids, command: 'confirm-test', interactive: true });
  t.after(() => service.cancel(view.id));
  const waitFor = async predicate => { for (let i = 0; i < 100; i++) { if (predicate()) return; await new Promise(r => setTimeout(r, 5)); } throw new Error('State did not settle'); };
  const job = service.jobs.get(view.id);
  assert.equal(started.length, 4);
  service.cancelTarget(job.id, ids[4], true); // queued target must never connect
  service.cancelTarget(job.id, ids[0], true); // active target is stopped independently
  await waitFor(() => started.includes(ids[5]));
  assert.ok(!started.includes(ids[4]));
  assert.equal(job.results[0].status, 'cancelled'); assert.equal(job.results[0].removed, true);
  assert.equal(job.results[4].removed, true);
  assert.equal(job.results[1].status, 'running');
  assert.throws(() => service.writeInput(job.id, [ids[1], ids[0]], 'y\r'), /no longer active/);
  assert.deepEqual(written, [], 'validate all recipients before sending any input');
  service.writeInput(job.id, [ids[1], ids[2], ids[3], ids[5]], 'y\r');
  await waitFor(() => job.status === 'completed');
  assert.equal(job.results.filter(r => r.status === 'succeeded').length, 4);
  assert.deepEqual(written.map(r => r[0]), [ids[1], ids[2], ids[3], ids[5]]);
  assert.throws(() => service.writeInput(job.id, [ids[1]], 'y\r'), /not running/);
  const safe = service.jobView(job); assert.equal(safe.targetControllers, undefined); assert.equal(safe.controls, undefined);
  assert.match(safe.results[1].terminal, /Continue.*Confirmed/);
});
