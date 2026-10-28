const { app, BrowserWindow, ipcMain, dialog, safeStorage, protocol, net, session, clipboard, ClipboardItem } = require('electron');
const path = require('node:path');
const { pathToFileURL } = require('node:url');
const { Store } = require('./store.cjs');
const { SSH } = require('./ssh.cjs');
const { Service } = require('./service.cjs');
const { Files } = require('./files.cjs');
const fs = require('node:fs');
const { NetworkConfig } = require('./network-config.cjs');
const { Gateways } = require('./gateways.cjs');
const { Routes } = require('./routes.cjs');
const { Backups, decode, limit: backupLimit } = require('./backups.cjs');
const { startBroker, runBridge } = require('./mcp.cjs');
const { Team } = require('./team.cjs');
const { Forwards } = require('./forwards.cjs');
const { Diagnostics } = require('./diagnostics.cjs');

app.setName('Connector');
if (process.env.CONNECTOR_TEST_DATA) app.setPath('userData', process.env.CONNECTOR_TEST_DATA);
protocol.registerSchemesAsPrivileged([{ scheme: 'app', privileges: { standard: true, secure: true, supportFetchAPI: true } }]);
const bridgeMode = process.argv.includes('--mcp');
let window, service, broker, files, routes, gateways, team, forwards, diagnostics;
const vault = {
  available: () => safeStorage.isEncryptionAvailable() && (process.platform !== 'linux' || safeStorage.getSelectedStorageBackend() !== 'basic_text'),
  encrypt: value => safeStorage.encryptString(value).toString('base64'),
  decrypt: value => { if (!vault.available()) throw new Error('OS credential vault is locked or unavailable'); return safeStorage.decryptString(Buffer.from(value, 'base64')); }
};
function emit(type, data) { if (type === 'terminal' || type === 'terminal-size') team?.terminal(data); if (window && !window.isDestroyed()) window.webContents.send('connector:event', { type, ...data }); }
function mcpConfig() { return { mcpServers: { connector: { command: process.execPath, args: [path.join(__dirname, 'bridge.cjs'), app.getPath('userData')], env: { ELECTRON_RUN_AS_NODE: '1' } } } }; }
function register(name, fn) {
  ipcMain.handle(name, async (event, ...args) => {
    if (!window || event.sender !== window.webContents || event.senderFrame !== window.webContents.mainFrame || !event.senderFrame.url.startsWith('app://connector/')) throw new Error('Untrusted IPC sender');
    return fn(...args);
  });
}
async function launch() {
  const directory = app.getPath('userData');
  if (bridgeMode) { await runBridge(directory); app.quit(); return; }
  if (!app.requestSingleInstanceLock()) { app.quit(); return; }
  app.on('second-instance', () => { if (window) { if (window.isMinimized()) window.restore(); window.show(); window.focus(); } });
  protocol.handle('app', request => {
    const url = new URL(request.url);
    const files = new Set(['/index.html', '/app.js', '/app.css']);
    if (url.hostname !== 'connector' || !files.has(url.pathname)) return new Response('Not found', { status: 404 });
    return net.fetch(pathToFileURL(path.join(__dirname, '..', 'dist', url.pathname.slice(1))).toString());
  });
  session.defaultSession.setPermissionRequestHandler((_wc, _permission, callback) => callback(false));
  session.defaultSession.setPermissionCheckHandler(() => false);
  const store = await Store.open(directory, vault);
  const network = new NetworkConfig(store);
  const runtime = app.isPackaged ? path.join(process.resourcesPath, 'vpn-runtime') : path.join(app.getAppPath(), 'vpn-runtime');
  gateways = new Gateways(network, vault, runtime, emit);
  routes = new Routes(network, gateways);
  const backups = new Backups(store, network), imports = new Map();
  const ssh = new SSH(store, vault, async (server, fingerprint) => {
    if (!window || window.isDestroyed()) return false;
    const response = await dialog.showMessageBox(window, { type: 'warning', title: 'Verify SSH server identity', buttons: ['Cancel', 'Trust this host'], defaultId: 0, cancelId: 0,
      message: `First connection to ${server.host}:${server.port}`,
      detail: `Route: ${server.routeName || 'Direct'}\nFingerprint:\n${fingerprint}\n\nVerify this fingerprint through a trusted channel before accepting. It will be pinned separately for this route.` });
    return response.response === 1;
  }, emit, routes);
  service = new Service(store, ssh, emit);
  files = new Files(store, ssh, vault, emit);
  forwards = new Forwards(store, ssh, emit);
  diagnostics = new Diagnostics(routes, network, emit);
  team = new Team(store, network, { emit, sessions: () => [...ssh.sessions].filter(([,s]) => s.stream).map(([sessionId,s]) => ({ sessionId, name:s.name, serverId:s.serverId, cols:s.cols, rows:s.rows })),
    invalidateServer: id => { routes.invalidate(id); ssh.closeServer(id); files.invalidateServer(id); forwards.invalidateServer(id); for (const job of service.jobs.values()) if (job.results.some(r => r.serverId === id)) service.cancelTarget(job.id, id); },
    writeSession:(id,data)=>{if(!ssh.sessions.get(id)?.stream)throw new Error('Source terminal closed');ssh.write(id,data);},
    invalidateVPN: id => gateways.stop(id) });
  ssh.authorize = (profile, capability) => team.assert(profile, capability);
  ssh.sharedAgent = profile => team.agentFor(profile);
  gateways.authorize = profile => { if (profile.shared) { const permission = ['terminal','exec','files','forward'].find(k => profile.shared.permissions[k]); if (!permission) throw new Error('Key has no VPN usage permissions'); team.assert(profile, permission); } };
  broker = await startBroker(directory, service);
  register('state', () => ({ ...service.state(), forwards:forwards.state(), team: team.state(), vpns: network.vpns(), routeRules: network.rules(), gateways: gateways.state(), runtimeAvailable: fs.existsSync(path.join(runtime, 'manifest.json')), vaultAvailable: vault.available(), mcpConfig: mcpConfig() }));
  register('forward:save', (input,id) => forwards.save(input,id));
  register('forward:remove', id => forwards.remove(id));
  register('forward:stop', id => forwards.stop(id));
  register('forward:start', async id => {
    const p=forwards.get(id),s=store.get(p.serverId),fingerprint=ssh.securitySnapshot(s),planned=JSON.stringify(p);ssh.authorize?.(s,'forward');
    const answer=await dialog.showMessageBox(window,{type:'question',buttons:['Cancel','Start port forward'],defaultId:0,cancelId:0,message:`Start ${p.kind} port forwarding through ${s.name}?`,detail:`${p.kind==='local'?'This computer listens':'SSH server listens'}: ${p.listenHost}:${p.listenPort||'automatic'}\n${p.kind==='local'?'Destination reached from the SSH server':'Destination reached from this computer'}: ${p.targetHost}:${p.targetPort}\n\nA bind address other than loopback can expose the forwarded service to other machines. Remote binding is also controlled by the SSH server’s AllowTcpForwarding, PermitListen and GatewayPorts settings. This tunnel uses its own SSH connection and stops when you stop it or close Connector.`});
    if(answer.response!==1)return null;if(JSON.stringify(forwards.get(id))!==planned||ssh.securitySnapshot(store.get(p.serverId))!==fingerprint)throw new Error('Tunnel or SSH route changed during review; try again');return forwards.start(id);
  });
  register('server:save', (input, id) => { if (input.routeMode === 'vpn' && network.get(input.vpnId).shared) throw new Error('Shared VPNs cannot be assigned to local profiles'); const result = store.put(input, id); if (id) routes.invalidate(id); service.changed(); return result; });
  register('server:copy', id => { const result = store.duplicate(id); service.changed(); return result; });
  register('vpn:copy', id => { const result = network.duplicate(id); service.changed(); return result; });
  register('team:start', input => team.start(input));
  register('team:stop', () => team.stop());
  register('team:create-key', async input => {
    const response = await dialog.showMessageBox(window, { type: 'warning', buttons: ['Cancel', 'Create sharing key'], defaultId:0, cancelId:0, message:'Share these connection profiles?', detail:`${input.serverIds?.length || 0} connections, ${input.vpnIds?.length || 0} VPNs. Credentials: ${input.permissions?.credentials ? 'INCLUDED — recipients can recover and retain them. Revoking a key cannot revoke SSH/VPN credentials already delivered. Rotate those credentials separately if needed.' : 'Not included — recipients need their own SSH agent; password/VPN profiles need credentials.'}\nLive viewers see all subsequent terminal output, including any secrets printed. Share invitation keys through a trusted channel.` });
    return response.response === 1 ? team.createKey(input) : null;
  });
  register('team:update-key', (id, input) => team.updateKey(id, input));
  register('team:revoke', (id, remove) => team.revoke(id, !!remove));
  register('team:add-client', input => team.addClient(input));
  register('team:set-client', (id, enabled, remove) => team.setClient(id, enabled, !!remove));
  register('team:cast', (sessionId, keyId) => team.startCast(sessionId, keyId));
  register('team:stop-cast', id => team.stopCast(id));
  register('team:watch', (id, castId) => team.watchClient(id, castId));
  register('team:collaborate', (castId,peerId,enabled) => team.setCollaboration(castId,peerId,enabled));
  register('team:live-input', (id,castId,data) => team.writeLive(id,castId,data));
  register('diagnostics:start', input => diagnostics.start(input));
  register('diagnostics:write', (id,data,encoding) => diagnostics.write(id,data,encoding));
  register('diagnostics:stop', id => diagnostics.stop(id));
  register('team:copy-invite', value => { require('./team.cjs').parseInvite(value); return clipboard.writeText(value); });
  register('team:persist', async (kind, id) => {
    const profile = kind === 'server' ? store.get(id) : kind === 'vpn' ? network.get(id) : null;
    if (!profile?.shared) throw new Error('Choose a shared connection or VPN');
    const response = await dialog.showMessageBox(window, { type:'question', buttons:['Cancel','Save independent local copy'], defaultId:0, cancelId:0, message:`Persist ${profile.name} locally?`, detail: profile.auth === 'agent' && profile.shared.permissions.credentials ? 'The profile and any required VPN will be copied. Agent private keys cannot be extracted: this saved connection still needs the original sharing server and a valid grant to authenticate.' : 'This creates an independent local copy, including delivered credentials and any required VPN. It will remain after revocation or removal of the sharing server and will not receive future profile updates. Missing credentials must be configured separately.' });
    return response.response === 1 ? team.persist(kind,id) : null;
  });
  register('server:route-many', async (ids, routeMode, vpnId) => {
    if (!['direct', 'vpn', 'auto'].includes(routeMode)) throw new Error('Choose an explicit routing mode');
    if (!Array.isArray(ids) || !ids.length || ids.length > 2000 || new Set(ids).size !== ids.length) throw new Error('Select 1–2000 distinct connections');
    const vpn = routeMode === 'vpn' ? network.get(vpnId) : null;
    if (vpn?.shared) throw new Error('Shared VPNs cannot be assigned to local profiles');
    const records = ids.map(id => { const previous = store.get(id); if (previous.shared) throw new Error('Shared profiles are managed by their owner'); return { ...previous, ...require('./core.cjs').normalizeServer({ ...previous, routeMode, vpnId }, id) }; });
    const answer = await dialog.showMessageBox(window, { type: 'question', buttons: ['Cancel', 'Apply connection routes'], defaultId: 0, cancelId: 0, message: `Change the route for ${records.length} connection(s)?`, detail: `Route: ${vpn ? 'VPN: ' + vpn.name : routeMode}\n${records.map(r => r.name).slice(0, 30).join('\n')}\n\nActive connections for these profiles will close. SSH passwords and keys are unchanged.` });
    if (answer.response !== 1) return null;
    const before = store.db.export(), Database = store.db.constructor;
    try { store.db.run('BEGIN'); for (const record of records) store.db.run('UPDATE servers SET data=? WHERE id=?', [JSON.stringify(record), record.id]); store.db.run('INSERT INTO audit(time,action,detail) VALUES (?,?,?)', [new Date().toISOString(), 'route.connections.updated', `${records.length} connections: ${routeMode}`]); store.db.run('COMMIT'); store.save(); }
    catch (error) { try { store.db.close(); } catch {} store.db = new Database(before); throw error; }
    ids.forEach(id => routes.invalidate(id)); service.changed(); return { updated: records.length };
  });
  register('server:remove', async id => {
    const server = store.get(id);
    const answer = await dialog.showMessageBox(window, { type: 'question', buttons: ['Cancel', 'Remove profile'], defaultId: 0, cancelId: 0, message: `Remove ${server.name} from Connector?`, detail: 'This removes the local connection profile. The remote server is not deleted.' });
    if (answer.response === 1) { store.remove(id); service.changed(); return true; } return false;
  });
  register('key:choose', async () => { const result = await dialog.showOpenDialog(window, { title: 'Choose an SSH private key', properties: ['openFile'] }); return result.canceled ? null : result.filePaths[0]; });
  register('ssh:open', (id, cols, rows) => ssh.open(id, cols, rows));
  register('terminal:fullscreen', enabled => { window.setFullScreen(enabled === true); emit('terminal-fullscreen', { enabled: enabled === true }); });
  register('ssh:open-many', ids => ssh.openMany(ids, result => emit('connection', result)));
  register('ssh:write', (id, data) => ssh.write(id, data));
  register('ssh:resize', (id, cols, rows) => ssh.resize(id, cols, rows));
  register('ssh:close', id => ssh.close(id));
  register('batch:run', async input => {
    const plan = service.plan(input);
    const result = await dialog.showMessageBox(window, { type: 'warning', buttons: ['Cancel', 'Run on selected servers'], defaultId: 0, cancelId: 0,
      message: `Execute on ${plan.serverNames.length} server(s)?`, detail: `${plan.serverNames.join('\n')}\n\nCommand:\n${plan.command}\n\nMode: ${plan.interactive ? 'Interactive PTY (manual keyboard input enabled)' : 'Non-interactive command'}\nTimeout: ${plan.timeout}s per server. Cancellation cannot guarantee a remote process is stopped.` });
    if (result.response !== 1) return null;
    if (plan.serverIds.some((id, i) => ssh.securitySnapshot(store.get(id)) !== plan.fingerprints[i])) throw new Error('A target or route changed during confirmation. Review and retry.');
    return service.run(plan);
  });
  register('batch:cancel', id => service.cancel(id));
  register('batch:cancel-target', (id, serverId, remove) => service.cancelTarget(id, serverId, !!remove));
  register('batch:input', (id, serverIds, data) => service.writeInput(id, serverIds, data));
  register('batch:resize', (id, serverId, cols, rows) => service.resizeTarget(id, serverId, cols, rows));
  register('files:state', () => files.state());
  register('files:open', id => files.open(id));
  register('files:close', id => files.close(id));
  register('files:list', (id, directory) => files.listing(id, directory));
  register('files:mkdir', (id, directory, name) => files.mkdir(id, directory, name));
  register('files:cancel', id => files.cancel(id));
  register('files:local-folder', async () => { const result = await dialog.showOpenDialog(window, { title: 'Choose a local folder', properties: ['openDirectory'] }); return result.canceled ? null : result.filePaths[0]; });
  register('files:transfer', async input => {
    const plan = await files.prepare(input);
    const direct = plan.route === 'direct';
    const answer = await dialog.showMessageBox(window, { type: direct ? 'warning' : 'question', buttons: ['Cancel', 'Transfer files'], defaultId: 0, cancelId: 0,
      message: `Copy ${plan.files.length} file(s) from ${plan.from.name} to ${plan.to.name}?`,
      detail: `${plan.sourceBase}\n→ ${plan.destinationBase}\n\n${plan.totalBytes.toLocaleString()} bytes. Existing files will not be replaced.\n\n${direct ? 'DIRECT server-to-server SFTP: file contents travel only between servers. The source must run Python 3 and OpenSSH 9+. The destination password will be temporarily available to the source user in memory for this operation. Only proceed if you trust the source server.' : 'File contents stream between this computer and the selected server.'}` });
    return answer.response === 1 ? files.start(plan) : null;
  });
  register('ai:enable', enabled => service.setAI(enabled));
  register('vpn:save', async (input, id) => {
    if (input.protocol === 'l2tp') {
      const answer = await dialog.showMessageBox(window, { type: 'warning', buttons: ['Cancel', 'Save plain L2TP profile'], defaultId: 0, cancelId: 0, message: 'This VPN profile does not use IPsec.', detail: 'L2TP alone does not encrypt its tunnel or protect PPP authentication like IPsec. SSH remains encrypted. Use this mode only when your VPN server requires it.' });
      if (answer.response !== 1) return null;
    }
    const saved = network.saveVPN(input, id); if (id) gateways.stop(id); service.changed(); return saved;
  });
  register('vpn:remove', id => { network.removeVPN(id); gateways.stop(id); service.changed(); });
  register('vpn:start', async id => { await gateways.ensure(id); return gateways.state(); });
  register('vpn:stop', id => gateways.stop(id));
  register('route:save', (input, id) => { const result = network.saveRule(input, id); routes.invalidate(); service.changed(); return result; });
  register('route:remove', id => { network.removeRule(id); routes.invalidate(); service.changed(); });
  register('route:preview', id => { const route = routes.select(store.get(id)); return { action: route.action, name: route.name, key: route.key }; });
  register('backup:export', async options => {
    const content = await backups.export(options), encrypted = !!options.passphrase;
    const result = await dialog.showSaveDialog(window, { title: 'Export connection and VPN profiles', defaultPath: 'connector-profiles.' + (encrypted ? 'cxb' : 'json'), filters: [{ name: encrypted ? 'Encrypted Connector backup' : 'Connector profiles (no credentials)', extensions: [encrypted ? 'cxb' : 'json'] }] });
    if (result.canceled || !result.filePath) return null;
    const temporary = result.filePath + '.tmp-' + require('node:crypto').randomUUID(); try { fs.writeFileSync(temporary, content, { mode: 0o600 }); fs.renameSync(temporary, result.filePath); } catch (error) { try { fs.unlinkSync(temporary); } catch {} throw error; } store.audit('backup.exported', encrypted ? 'Encrypted backup' : 'Metadata only'); return { filename: path.basename(result.filePath) };
  });
  register('backup:open', async () => {
    for (const [id, value] of imports) if (value.expires < Date.now()) imports.delete(id);
    if (imports.size >= 4) throw new Error('Close an existing import preview first');
    const result = await dialog.showOpenDialog(window, { title: 'Import Connector profiles', properties: ['openFile'], filters: [{ name: 'Connector profiles', extensions: ['cxb', 'json'] }] });
    if (result.canceled) return null;
    const filename = result.filePaths[0]; if (fs.statSync(filename).size > backupLimit) throw new Error('Backup exceeds 10 MiB');
    const content = fs.readFileSync(filename, 'utf8'); let header; try { header = JSON.parse(content); } catch { throw new Error('Invalid backup JSON'); }
    const token = require('node:crypto').randomUUID(); imports.set(token, { content, expires: Date.now() + 300000 });
    return { token, filename: path.basename(filename), encrypted: header.encrypted === true };
  });
  register('backup:preview', async (token, passphrase) => {
    const value = imports.get(token); if (!value || value.expires < Date.now()) throw new Error('Import preview expired; select the file again');
    value.payload = await decode(value.content, passphrase); return backups.preview(value.payload);
  });
  register('backup:cancel', token => imports.delete(token));
  register('backup:apply', async (token, enableRules) => {
    const value = imports.get(token); if (!value?.payload || value.expires < Date.now()) throw new Error('Import preview expired; select the file again');
    const preview = backups.preview(value.payload);
    const answer = await dialog.showMessageBox(window, { type: 'question', buttons: ['Cancel', 'Import as new profiles'], defaultId: 0, cancelId: 0, message: `Import ${preview.servers} connections and ${preview.vpns} VPNs?`, detail: `${preview.rules} routing rules. ${preview.plainVPNs} plain L2TP profiles without IPsec. Existing profiles will not be overwritten. Imported routing rules will be ${enableRules ? 'enabled; active routed connections will close to apply the new policy' : 'disabled until you enable them'}. Missing credentials must be configured before connecting. SSH host trust is not imported.` });
    if (answer.response !== 1) return null;
    const result = backups.import(value.payload, enableRules === true); imports.delete(token); if (enableRules) routes.invalidate(); service.changed(); return { servers: result.servers.length, vpns: result.vpns, rules: result.rules };
  });
  register('config:copy', () => clipboard.writeText(JSON.stringify(mcpConfig(), null, 2)));
  register('terminal:copy', value => {
    if (!value || typeof value.text !== 'string' || typeof value.html !== 'string' || Buffer.byteLength(value.text) > 8 * 1024 * 1024 || Buffer.byteLength(value.html) > 32 * 1024 * 1024) throw new Error('Terminal selection is too large');
    return clipboard.write([new ClipboardItem({ 'text/plain': value.text, 'text/html': value.html })]);
  });
  register('terminal:clipboard', async () => {
    const text = await clipboard.readText();
    if (Buffer.byteLength(text) > 1024 * 1024) throw new Error('Clipboard exceeds the 1 MiB terminal input limit');
    return text;
  });
  register('ai:decide', (id, approve) => service.decide(id, !!approve));
  window = new BrowserWindow({ width: 1440, height: 940, minWidth: 1060, minHeight: 720, backgroundColor: '#0b0f16', autoHideMenuBar: true,
    show: !process.argv.includes('--hidden'), title: 'Connector', icon: path.join(__dirname, '..', 'assets', 'icon.png'),
    webPreferences: { preload: path.join(__dirname, 'preload.cjs'), contextIsolation: true, nodeIntegration: false, sandbox: true, webSecurity: true, spellcheck: false } });
  window.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
  window.on('leave-full-screen', () => emit('terminal-fullscreen', { enabled: false }));
  window.webContents.on('before-input-event', (event, input) => {
    if (input.type !== 'keyDown') return;
    if (input.key === 'F11' || (input.key === 'Escape' && window.isFullScreen())) { event.preventDefault(); const enabled = input.key === 'F11' && !window.isFullScreen(); window.setFullScreen(enabled); emit('terminal-fullscreen', { enabled }); }
  });
  window.webContents.on('will-navigate', event => event.preventDefault());
  window.webContents.on('will-attach-webview', event => event.preventDefault());
  window.loadURL('app://connector/index.html');
}
app.whenReady().then(launch).catch(error => { console.error(error); if (!bridgeMode) dialog.showErrorBox('Connector could not start', error.message); app.exit(1); });
app.on('window-all-closed', () => app.quit());
app.on('before-quit', () => { diagnostics?.shutdown(); forwards?.shutdown(); team?.shutdown(); files?.shutdown(); service?.shutdown(); routes?.shutdown(); broker?.close(); });
