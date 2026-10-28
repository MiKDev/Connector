const crypto = require('node:crypto');
const tls = require('node:tls');
const { identity, channel, connect } = require('./team-transport.cjs');
const { text, snapshot, timingEqual, normalizeServer, publicServer } = require('./core.cjs');
const { normalizeVPN, publicVPN } = require('./network-config.cjs');
const { readPrivateKey, validatePrivateKey, keyFileFingerprint } = require('./shared-credentials.cjs');
const { SharedAgent, nativeAgent, publicBlob, validateAuthentication } = require('./team-agent.cjs');
const hash = value => crypto.createHash('sha256').update(value).digest('hex');
const uid = () => crypto.randomUUID();
function parseInvite(value) {
  if (typeof value !== 'string' || value.length > 4000 || !value.startsWith('connector-share:')) throw new Error('Invalid sharing invitation');
  let v; try { v = JSON.parse(Buffer.from(value.slice(16), 'base64url')); } catch { throw new Error('Invalid invitation encoding'); }
  if (v.v !== 1 || typeof v.host !== 'string' || !/^[a-zA-Z0-9.:[\]-]{1,253}$/.test(v.host) || !Number.isInteger(v.port) || v.port < 1 || v.port > 65535 || !/^[a-f0-9]{64}$/.test(v.fingerprint) || !/^[a-f0-9-]{36}$/.test(v.id) || !/^[a-f0-9]{64}$/.test(v.token)) throw new Error('Invalid sharing invitation fields');
  return { v: 1, host: v.host, port: v.port, fingerprint: v.fingerprint, id: v.id, token: v.token };
}
class Team {
  constructor(store, network, hooks = {}) {
    this.store = store; this.network = network; this.hooks = hooks; this.listener = null; this.starting = false; this.epoch = 0; this.keyCache = new Map(); this.rawSockets = new Set(); this.peers = new Set(); this.links = new Map(); this.casts = new Map(); this.closed = false;
    store.db.run('CREATE TABLE IF NOT EXISTS team_meta (id TEXT PRIMARY KEY,data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS team_keys (id TEXT PRIMARY KEY,data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS team_clients (id TEXT PRIMARY KEY,data TEXT NOT NULL); CREATE TABLE IF NOT EXISTS team_revisions (id TEXT PRIMARY KEY,data TEXT NOT NULL);');
    this.timer = setInterval(() => this.tick(), 2000); this.timer.unref();
  }
  rows(table) { return this.store.rows('SELECT data FROM ' + table).map(r => JSON.parse(r.data)); }
  put(table, value) { this.store.db.run('INSERT OR REPLACE INTO ' + table + ' VALUES (?,?)', [value.id, JSON.stringify(value)]); this.store.save(); }
  emit(type, data = {}) { this.hooks.emit?.(type, data); }
  changed() { this.emit('changed'); }
  identity() {
    let i = this.rows('team_meta').find(r => r.id === 'identity');
    if (!i) { if (!this.store.vault.available()) throw new Error('Unlock OS credential vault first'); const created = identity(); i = { id: 'identity', cert: created.cert, fingerprint: created.fingerprint, key: this.store.vault.encrypt(created.key) }; this.put('team_meta', i); }
    return { ...i, key: this.store.vault.decrypt(i.key) };
  }
  state() {
    return { server: this.listener ? { listening: true, host: this.listenHost, port: this.listener.address()?.port, fingerprint: this.rows('team_meta').find(r => r.id === 'identity')?.fingerprint } : { listening: false },
      keys: this.rows('team_keys').map(({ tokenHash, ...v }) => ({ ...v, clients: [...this.peers].filter(p => p.keyId === v.id && !p.socket.destroyed).length })),
      clients: this.rows('team_clients').map(({ invitation, ...v }) => ({ ...v, status: this.links.get(v.id)?.status || 'disconnected', error: this.links.get(v.id)?.error || '', casts: this.links.get(v.id)?.casts || [] })),
      casts: [...this.casts.values()].map(({ chunks, bytes, controllers, ...v }) => ({...v,viewers:[...this.peers].filter(p=>p.keyId===v.keyId&&!p.socket.destroyed).map(p=>({id:p.id,name:p.name,address:p.socket.remoteAddress,watching:p.watching===v.id,canInput:controllers.has(p.id)}))})),
      sessions: this.hooks.sessions?.() || [] };
  }
  async start(input) {
    if (this.listener || this.starting || this.closed) throw new Error('Sharing server is already running or starting');
    const host = input.host || '0.0.0.0', port = Number(input.port ?? 8743);
    if (!require('node:net').isIP(host) || !Number.isInteger(port) || port < 0 || port > 65535) throw new Error('Choose a bind IP and port');
    const i = this.identity();
    const listener = tls.createServer({ key: i.key, cert: i.cert, minVersion: 'TLSv1.3', maxVersion: 'TLSv1.3', handshakeTimeout: 10000 }, socket => this.accept(socket));
    listener.maxConnections = 64;
    listener.on('tlsClientError', () => {});
    listener.on('connection', socket => { this.rawSockets.add(socket); socket.once('close', () => this.rawSockets.delete(socket)); socket.on('error', () => {}); socket.setTimeout(45000, () => socket.destroy()); });
    this.starting = true; const epoch = this.epoch;
    try { await new Promise((resolve, reject) => { listener.once('error', reject); listener.listen(port, host, resolve); }); }
    finally { this.starting = false; }
    if (this.closed || this.epoch !== epoch) { listener.close(); throw new Error('Sharing server closed during startup'); }
    listener.on('error', () => this.stop()); this.listener = listener; this.listenHost = host;
    this.store.audit('team.server.started', `${host}:${listener.address().port}`); this.changed(); return this.state().server;
  }
  stop() {
    this.epoch++;
    this.keyCache.clear();
    for (const p of this.peers) p.socket.destroy();
    for (const socket of this.rawSockets) socket.destroy(); this.rawSockets.clear();
    this.peers.clear(); this.casts.clear(); this.listener?.close(); this.listener = null; this.changed();
  }
  keyInput(input, previous) {
    const ids = (list, allowed, name) => { if (!Array.isArray(list) || list.length > 2000 || list.some(id => typeof id !== 'string' || !allowed.some(v => v.id === id))) throw new Error('Invalid shared ' + name); return [...new Set(list)]; };
    const servers = ids(input.serverIds || [], this.store.all(true).filter(s => !s.shared), 'connections');
    const vpns = ids(input.vpnIds || [], this.network.vpns(true).filter(v => !v.shared), 'VPNs');
    for (const id of servers) { const s = this.store.get(id); if (s.routeMode === 'auto') throw new Error('Bind a shared connection to Direct or a specific VPN first'); if (s.agentDelegate) throw new Error('A delegated agent cannot be shared onward; use an identity you own'); if (s.vpnId && !vpns.includes(s.vpnId)) throw new Error('Select the VPN required by every shared connection'); if (s.auth === 'key' && input.permissions?.credentials) readPrivateKey(s, this.store.vault); }
    const permissions = Object.fromEntries(['terminal','exec','files','forward','credentials','live'].map(k => [k, input.permissions?.[k] === true]));
    return { id: previous?.id || uid(), name: text(input.name, 'key name', 80), serverIds: servers, vpnIds: vpns, permissions, revision: (previous?.revision || 0) + 1, revoked: false, createdAt: previous?.createdAt || new Date().toISOString() };
  }
  createKey(input) {
    if (!this.listener) throw new Error('Start the sharing server before creating an invitation');
    const value = this.keyInput(input), token = crypto.randomBytes(32).toString('hex');
    const host = text(input.advertiseHost, 'server address clients can reach', 253);
    const invite = { v: 1, host, port: this.listener.address().port, fingerprint: this.identity().fingerprint, id: value.id, token };
    const invitation = 'connector-share:' + Buffer.from(JSON.stringify(invite)).toString('base64url'); parseInvite(invitation);
    this.put('team_keys', { ...value, tokenHash: hash(token) }); this.store.audit('team.key.created', value.name); this.changed();
    return { id: value.id, invitation };
  }
  updateKey(id, input) {
    const old = this.rows('team_keys').find(k => k.id === id); if (!old || old.revoked) throw new Error('Key no longer active');
    const value = { ...this.keyInput(input, old), tokenHash: old.tokenHash }; this.put('team_keys', value);
    for (const p of this.peers) if (p.keyId === id) { this.clearControl(p); this.syncPeer(p, true); }
    this.store.audit('team.key.updated', value.name); this.changed();
  }
  revoke(id, remove = false) {
    const key = this.rows('team_keys').find(k => k.id === id); if (!key) throw new Error('Key does not exist');
    // Persist first: no future authentication may succeed even if a send fails.
    if (remove) { this.store.db.run('DELETE FROM team_keys WHERE id=?', [id]); this.store.save(); }
    else this.put('team_keys', { ...key, tokenHash: '', revoked: true, revision: key.revision + 1 });
    for (const p of this.peers) if (p.keyId === id) { p.send({ type: 'revoked' }); p.socket.end(); setTimeout(() => p.socket.destroy(), 250).unref(); }
    for (const [castId, cast] of this.casts) if (cast.keyId === id) this.casts.delete(castId);
    this.store.audit(remove ? 'team.key.deleted' : 'team.key.revoked', key.name); this.changed();
  }
  revision(kind, profile) {
    const { distro, ...revisionFields } = profile;
    const id = kind + ':' + profile.id, digest = snapshot(revisionFields), old = this.rows('team_revisions').find(r => r.id === id);
    if (old?.hash === digest) return old.version;
    const version = (old?.version || 0) + 1; this.put('team_revisions', { id, hash: digest, version }); return version;
  }
  privateKeyFor(profile, fileFingerprint) {
    const fingerprint = snapshot({ keyPath:profile.keyPath, keySource:profile.keySource, secret:profile.secret, privateKeySecret:profile.privateKeySecret, fileFingerprint });
    const cached = this.keyCache.get(profile.id); if (cached?.fingerprint === fingerprint) return cached.value;
    this.keyCache.delete(profile.id); const value = readPrivateKey(profile,this.store.vault);
    if (this.keyCache.size >= 64) this.keyCache.delete(this.keyCache.keys().next().value);
    this.keyCache.set(profile.id,{fingerprint,value}); return value;
  }
  manifest(key) {
    const servers = key.serverIds.flatMap(id => { let p; try { p = this.store.get(id); } catch { return []; } if (p.shared || p.agentDelegate || p.routeMode === 'auto' || (p.vpnId && !key.vpnIds.includes(p.vpnId))) return [];
      const { secret, privateKeySecret, distro, ...safe } = p;
      const fileFingerprint=keyFileFingerprint(p);
      const privateKey = p.auth === 'key' && key.permissions.credentials ? this.privateKeyFor(p,fileFingerprint) : undefined;
      if (p.auth === 'key') { safe.keyPath = ''; safe.keySource = 'vault'; }
      return [{ ...safe, version: this.revision('server', { ...p, keyMaterialHash:fileFingerprint }), ...(privateKey ? { privateKey } : {}), ...(key.permissions.credentials && secret ? { credential: this.store.vault.decrypt(secret) } : {}) }]; });
    const vpns = key.vpnIds.flatMap(id => { let p; try { p = this.network.get(id); } catch { return []; } if (p.shared) return [];
      const { passwordSecret, pskSecret, ...safe } = p;
      return [{ ...safe, version: this.revision('vpn', p), ...(key.permissions.credentials ? { password: passwordSecret ? this.store.vault.decrypt(passwordSecret) : '', psk: pskSecret ? this.store.vault.decrypt(pskSecret) : '' } : {}) }]; });
    return { type: 'manifest', keyRevision: key.revision, permissions: key.permissions, servers, vpns };
  }
  accept(socket) {
    if (!this.listener || this.closed) { socket.destroy(); return; }
    const peer = { id:uid(), name:'Client', socket, keyId: null, digest: null, last: Date.now(), frames: 0, inputFrames:0, inputBytes:0, frameStart: Date.now() };
    this.peers.add(peer); const timeout = setTimeout(() => socket.destroy(), 10000); timeout.unref();
    socket.once('close', () => { clearTimeout(timeout); this.clearControl(peer); this.peers.delete(peer); this.changed(); });
    peer.send = channel(socket, message => {
      if (this.closed) return;
      peer.last = Date.now(); if (Date.now() - peer.frameStart > 10000) { peer.frameStart = Date.now(); peer.frames = peer.inputFrames = peer.inputBytes = 0; }
      if(message.type==='cast-input') { peer.inputBytes+=typeof message.data==='string'?Buffer.byteLength(message.data):65537; if(++peer.inputFrames>2000||peer.inputBytes>2097152){socket.destroy();return;} }
      else if (++peer.frames > 100) { socket.destroy(); return; }
      if (!peer.keyId) {
        const key = this.rows('team_keys').find(k => k.id === message.id && !k.revoked);
        if (message.type !== 'auth' || message.protocol !== 1 || !key || typeof message.token !== 'string' || !timingEqual(hash(message.token), key.tokenHash) || [...this.peers].filter(p => p.keyId === key.id).length >= 8) { peer.send({ type: 'denied' }); socket.end(); return; }
        peer.keyId = key.id; peer.name=typeof message.viewerName==='string'?message.viewerName.replace(/[\x00-\x1f\x7f]/g,'').slice(0,80)||'Client':'Client'; clearTimeout(timeout); this.syncPeer(peer, true); this.sendCastList(peer); this.changed(); return;
      }
      // Only the local operator can grant input to this exact connected peer.
      if (message.type === 'ping') peer.send({ type: 'pong' });
      else if (message.type === 'sync') this.syncPeer(peer);
      else if (message.type === 'watch') this.watch(peer, message.castId);
      else if (message.type === 'cast-input') this.receiveCastInput(peer,message);
      else if (message.type === 'agent') this.handleAgent(peer, message).catch(() => { if (!peer.socket.destroyed) peer.send({ type:'agent-result', requestId:message.requestId, error:'Shared agent request refused or agent unavailable' }); });
      else socket.destroy();
    });
  }
  syncPeer(peer, force = false) {
    const key = this.rows('team_keys').find(k => k.id === peer.keyId && !k.revoked);
    if (!key) { peer.send({ type: 'revoked' }); peer.socket.end(); return; }
    try { const manifest = this.manifest(key), digest = snapshot(manifest); if (force || digest !== peer.digest) { peer.digest = digest; peer.send(manifest); this.sendCastList(peer); } }
    catch { peer.socket.destroy(); }
  }
  async addClient(input) {
    const invite = parseInvite(input.invitation);
    if (this.rows('team_clients').length >= 20) throw new Error('Maximum 20 sharing servers');
    if (this.rows('team_clients').some(c => c.fingerprint === invite.fingerprint && c.keyId === invite.id)) throw new Error('This server/key is already added');
    if (!this.store.vault.available()) throw new Error('Unlock OS credential vault first');
    const value = { id: uid(), name: text(input.name, 'sharing server name', 80), viewerName:text(input.viewerName||require('node:os').hostname(),'viewer name',80), fingerprint: invite.fingerprint, keyId: invite.id, host: invite.host, port: invite.port, invitation: this.store.vault.encrypt(input.invitation), enabled: true };
    this.put('team_clients', value); this.connectClient(value.id); this.changed(); return value.id;
  }
  connectClient(id) {
    const client = this.rows('team_clients').find(c => c.id === id); if (!client || !client.enabled || this.closed) return;
    const old = this.links.get(id); if (old?.socket && !old.socket.destroyed) return;
    let invitation; try { invitation = parseInvite(this.store.vault.decrypt(client.invitation)); } catch { this.links.set(id, { status: 'error', error: 'Unlock OS credential vault to connect', retry: Date.now() + 5000 }); this.changed(); return; }
    const { socket, ready } = connect(invitation), link = { socket, status: 'connecting', last: Date.now(), casts: [], controls:new Map(), watching:null, lastPing: 0, pendingAgents: new Map() }; this.links.set(id, link);
    const authTimer = setTimeout(() => socket.destroy(), 15000); authTimer.unref();
    link.send = channel(socket, message => {
      if (this.closed || this.links.get(id) !== link || !this.rows('team_clients').some(c => c.id === id && c.enabled)) { socket.destroy(); return; }
      link.last = Date.now();
      if (message.type === 'manifest') {
        try { this.applyManifest(client, message); link.status = 'connected'; link.error = ''; clearTimeout(authTimer); this.changed(); }
        catch { link.error = 'Invalid shared profiles; connection closed'; socket.destroy(); }
      } else if (message.type === 'revoked' || message.type === 'denied') {
        client.enabled = false; this.put('team_clients', client); this.removeManaged(id); link.status = 'revoked'; link.error = 'Key revoked, deleted or refused by server'; socket.destroy();
      } else if (link.status === 'connected' && message.type === 'casts') {
        if (!Array.isArray(message.casts) || message.casts.length > 24) { socket.destroy(); return; } link.casts = message.casts; this.emit('team-casts', { clientId: id, casts: link.casts });
      } else if (link.status === 'connected' && message.type === 'cast-control') {
        if(typeof message.castId!=='string'||message.castId.length>80||typeof message.canInput!=='boolean'||(message.canInput&&(typeof message.grantId!=='string'||message.grantId.length>80))){socket.destroy();return;}
        if(message.canInput)link.controls.set(message.castId,message.grantId);else link.controls.delete(message.castId);
        this.emit('team-cast-control',{clientId:id,castId:message.castId,canInput:message.canInput});
      } else if (link.status === 'connected' && message.type === 'cast') {
        if (typeof message.castId !== 'string' || typeof message.data !== 'string' || message.data.length > 600000) { socket.destroy(); return; }
        const { type, ...payload } = message; this.emit('team-cast', { ...payload, clientId: id });
      } else if (link.status === 'connected' && message.type === 'agent-result') {
        const pending = link.pendingAgents.get(message.requestId); if (pending) { link.pendingAgents.delete(message.requestId); clearTimeout(pending.timer); if (message.error) pending.reject(new Error('Server SSH agent refused authentication')); else pending.resolve(message); }
      } else if (message.type !== 'pong') socket.destroy();
    });
    ready.then(() => link.send({ type: 'auth', protocol: 1, id: invitation.id, token: invitation.token,viewerName:client.viewerName||require('node:os').hostname() })).catch(() => { link.error ||= 'Cannot connect or sharing server identity mismatch'; });
    socket.on('error', () => { link.error ||= 'Sharing server unavailable'; });
    socket.once('close', () => { clearTimeout(authTimer); for (const pending of link.pendingAgents.values()) { clearTimeout(pending.timer); pending.reject(new Error('Sharing server disconnected')); } link.pendingAgents.clear(); if (this.closed) return; link.status = client.enabled ? 'disconnected' : 'revoked'; link.retry = Date.now() + 5000; link.casts = []; this.invalidateClient(id); this.emit('team-casts', { clientId: id, casts: [] }); this.changed(); });
    this.changed();
  }
  setClient(id, enabled, remove = false) {
    const client = this.rows('team_clients').find(c => c.id === id); if (!client) throw new Error('Sharing server not found');
    client.enabled = !!enabled;
    if (remove) { this.store.db.run('DELETE FROM team_clients WHERE id=?', [id]); this.store.save(); } else this.put('team_clients', client);
    this.links.get(id)?.socket?.destroy(); this.links.delete(id); this.invalidateClient(id);
    if (remove) this.removeManaged(id); else if (enabled) this.connectClient(id); this.changed();
  }
  managedId(clientId, kind, remoteId) { return hash(clientId + ':' + kind + ':' + remoteId).slice(0, 32); }
  applyManifest(client, message) {
    if (!Array.isArray(message.servers) || !Array.isArray(message.vpns) || message.servers.length > 2000 || message.vpns.length > 200 || !Number.isInteger(message.keyRevision) || message.keyRevision < 1 || !message.permissions) throw new Error('Invalid manifest');
    const currentClient = this.rows('team_clients').find(c => c.id === client.id);
    if ((currentClient?.keyRevision || 0) > message.keyRevision) throw new Error('Sharing access revision moved backwards');
    const permissions = Object.fromEntries(['terminal','exec','files','forward','credentials','live'].map(k => [k, message.permissions[k] === true]));
    if (permissions.credentials && !this.store.vault.available()) throw new Error('Unlock OS credential vault before receiving shared credentials');
    const versions = new Set(), vpns = [], servers = [];
    const meta = (p, kind) => {
      if (typeof p.id !== 'string' || p.id.length > 80 || !p.id || !Number.isInteger(p.version) || p.version < 1 || versions.has(kind + p.id)) throw new Error('Invalid shared profile version'); versions.add(kind + p.id);
      return { owner: client.id, remoteId: p.id, version: p.version, keyRevision: message.keyRevision, permissions, source: client.name };
    };
    for (const p of message.vpns) {
      const shared = meta(p, 'vpn'), value = normalizeVPN(p, this.managedId(client.id, 'vpn', p.id)); value.shared = shared;
      for (const k of ['password','psk']) if (permissions.credentials && p[k]) { if (typeof p[k] !== 'string' || p[k].length > 8192 || /[\r\n\0]/.test(p[k])) throw new Error('Invalid credential'); value[k + 'Secret'] = this.store.vault.encrypt(p[k]); }
      vpns.push(value);
    }
    for (const p of message.servers) {
      const shared = meta(p, 'server');
      if (!['agent','password','key'].includes(p.auth) || !['direct','vpn'].includes(p.routeMode)) throw new Error('Unsupported shared connection');
      const vpn = p.routeMode === 'vpn' ? vpns.find(v => v.shared.remoteId === p.vpnId) : null; if (p.routeMode === 'vpn' && !vpn) throw new Error('Missing shared VPN');
      const value = normalizeServer({ ...p, ...(p.auth === 'key' ? { keySource:'vault', keyPath:'' } : {}), vpnId: vpn?.id || '' }, this.managedId(client.id, 'server', p.id)); value.shared = shared;
      if (permissions.credentials && p.credential) { if (typeof p.credential !== 'string' || p.credential.length > 8192) throw new Error('Invalid credential'); value.secret = this.store.vault.encrypt(p.credential); }
      if (permissions.credentials && p.auth === 'key' && p.privateKey) value.privateKeySecret = this.store.vault.encrypt(validatePrivateKey(p.privateKey, p.credential));
      servers.push(value);
    }
    const oldServers = this.store.all(true).filter(p => p.shared?.owner === client.id), oldVPNs = this.network.vpns(true).filter(p => p.shared?.owner === client.id);
    for (const [oldList, newList] of [[oldServers, servers], [oldVPNs, vpns]]) for (const p of newList) if (oldList.some(old => old.id === p.id && old.shared.version > p.shared.version)) throw new Error('Shared profile version moved backwards');
    // Ignore encryption randomness / local normalization timestamps when deciding
    // whether an owner's unchanged revision should interrupt active sessions.
    const same = (old, p) => old && old.shared.version === p.shared.version && old.shared.keyRevision === p.shared.keyRevision && snapshot(old.shared.permissions) === snapshot(p.shared.permissions);
    const changes = oldServers.filter(old => !servers.some(p => p.id === old.id && same(old, p)));
    const vpnChanges = oldVPNs.filter(old => !vpns.some(p => p.id === old.id && same(old, p)));
    for (const p of servers) { const old = oldServers.find(o => o.id === p.id); if (same(old, p)) Object.assign(p, old); }
    for (const p of vpns) { const old = oldVPNs.find(o => o.id === p.id); if (same(old, p)) Object.assign(p, old); }
    const before = this.store.db.export(), Database = this.store.db.constructor;
    try {
      this.store.db.run('BEGIN');
      for (const p of [...oldServers, ...oldVPNs]) this.store.db.run('DELETE FROM ' + (p.shared && oldServers.includes(p) ? 'servers' : 'vpns') + ' WHERE id=?', [p.id]);
      for (const [table, list] of [['vpns', vpns], ['servers', servers]]) for (const p of list) this.store.db.run('INSERT OR REPLACE INTO ' + table + ' VALUES (?,?)', [p.id, JSON.stringify(p)]);
      const savedClient = { ...client, keyRevision: message.keyRevision, lastSync: new Date().toISOString(), enabled: true }; this.store.db.run('INSERT OR REPLACE INTO team_clients VALUES (?,?)', [client.id, JSON.stringify(savedClient)]);
      this.store.db.run('COMMIT'); this.store.save();
    } catch (error) { this.store.db.close(); this.store.db = new Database(before); throw error; }
    for (const p of changes) { this.hooks.invalidateServer?.(p.id); for (const dependent of this.store.all(true).filter(s => s.agentDelegate?.owner === p.shared.owner && s.agentDelegate.remoteId === p.shared.remoteId)) this.hooks.invalidateServer?.(dependent.id); }
    for (const p of vpnChanges) this.hooks.invalidateVPN?.(p.id);
  }
  invalidateClient(id) {
    for (const p of this.store.all(true).filter(s => s.shared?.owner === id || s.agentDelegate?.owner === id)) this.hooks.invalidateServer?.(p.id);
    for (const p of this.network.vpns(true).filter(s => s.shared?.owner === id)) this.hooks.invalidateVPN?.(p.id);
    this.emit('team-cast', { clientId: id, closed: true });
  }
  removeManaged(id) {
    this.invalidateClient(id);
    for (const [table, list] of [['servers', this.store.all(true)], ['vpns', this.network.vpns(true)]]) for (const p of list.filter(p => p.shared?.owner === id)) this.store.db.run('DELETE FROM ' + table + ' WHERE id=?', [p.id]);
    this.store.save(); this.changed();
  }
  assert(profile, capability = 'terminal') {
    if (profile.agentDelegate) { const managed = this.store.all(true).find(s => s.shared?.owner === profile.agentDelegate.owner && s.shared.remoteId === profile.agentDelegate.remoteId); if (!managed || !managed.shared.permissions.credentials) throw new Error('Delegated SSH agent access is no longer available'); if (['host','port','username'].some(k=>managed[k]!==profile[k])) throw new Error('Owner changed the delegated agent endpoint; persist the updated profile again'); this.assert(managed, capability); return; }
    if (!profile.shared) return;
    if (this.links.get(profile.shared.owner)?.status !== 'connected') throw new Error('Shared connection requires its sharing server to be online');
    if (!profile.shared.permissions?.[capability]) throw new Error('Sharing key does not allow ' + capability);
  }
  agentFor(profile) {
    const origin = profile.agentDelegate || profile.shared;
    if (profile.auth !== 'agent' || !origin) return null;
    const managed = profile.agentDelegate ? this.store.all(true).find(s => s.shared?.owner === origin.owner && s.shared.remoteId === origin.remoteId) : profile;
    if (!managed?.shared.permissions.credentials) { if (profile.agentDelegate) throw new Error('Delegated SSH agent unavailable'); return null; }
    return new SharedAgent(request => this.requestAgent(origin.owner, origin.remoteId, request));
  }
  requestAgent(owner, remoteId, request) {
    const link = this.links.get(owner); if (link?.status !== 'connected') return Promise.reject(new Error('Sharing server SSH agent is offline'));
    if (link.pendingAgents.size >= 32) return Promise.reject(new Error('Too many pending agent requests'));
    const requestId = uid();
    return new Promise((resolve,reject)=>{const timer=setTimeout(()=>{link.pendingAgents.delete(requestId);reject(new Error('Sharing agent request timed out'));},15000);timer.unref();link.pendingAgents.set(requestId,{resolve,reject,timer});link.send({type:'agent',requestId,profileId:remoteId,...request});});
  }
  async handleAgent(peer, message) {
    if (typeof message.requestId !== 'string' || message.requestId.length > 80 || peer.agentPending >= 8) throw new Error('Invalid agent request');
    const authorized = () => { const key=this.rows('team_keys').find(k=>k.id===peer.keyId&&!k.revoked); if(peer.socket.destroyed||!key?.permissions.credentials||!key.serverIds.includes(message.profileId)||!['terminal','exec','files','forward'].some(k=>key.permissions[k]))throw new Error('Agent not granted');const p=this.store.get(message.profileId);if(p.shared||p.agentDelegate||p.auth!=='agent')throw new Error('Not a local agent profile');return p; };
    const profile=authorized(), agent=this.hooks.agent?.() || nativeAgent(); peer.agentPending=(peer.agentPending||0)+1;
    const call=(method,...args)=>new Promise((resolve,reject)=>{const timer=setTimeout(()=>reject(new Error('Native agent timeout')),10000);timer.unref();agent[method](...args,(error,result)=>{clearTimeout(timer);if(error)reject(error);else resolve(result);});});
    try {
      const identities=await call('getIdentities'); if(!Array.isArray(identities)||identities.length>64)throw new Error('Too many agent identities');
      const keys=identities.map(publicBlob); let response;
      if(message.operation==='identities')response={keys:keys.map(k=>k.toString('base64'))};
      else if(message.operation==='sign') {
        if(typeof message.publicKey!=='string'||message.publicKey.length>32768||typeof message.data!=='string'||message.data.length>90000||!['','sha256','sha512'].includes(message.hash||''))throw new Error('Invalid signing request');
        const pub=Buffer.from(message.publicKey,'base64'),data=Buffer.from(message.data,'base64');if(!keys.some(k=>k.equals(pub)))throw new Error('Identity not loaded');validateAuthentication(data,pub,profile.username);authorized();
        const signature=await call('sign',pub,data,message.hash?{hash:message.hash}:{});response={signature:signature.toString('base64')};
      }else throw new Error('Unsupported agent operation');
      const current=authorized();if(current.updatedAt!==profile.updatedAt)throw new Error('Agent profile changed during authentication');peer.send({type:'agent-result',requestId:message.requestId,...response});
    } finally { peer.agentPending--; }
  }
  persist(kind, id) {
    if (!['server','vpn'].includes(kind)) throw new Error('Invalid shared resource type');
    const original=kind==='server'?this.store.get(id):this.network.get(id);if(!original.shared)throw new Error('Choose a managed shared profile');
    if(original.auth==='key'&&!original.privateKeySecret)throw new Error('Private key material was not delivered; enable credential sharing on the server');
    const clone=p=>{const {shared,...local}=p;return {...local,id:uid(),name:p.name.slice(0,72)+' (saved)',updatedAt:new Date().toISOString()};};
    const value=clone(original), records=[];
    if(kind==='server'&&original.vpnId){const vpn=this.network.get(original.vpnId),localVPN=clone(vpn);value.vpnId=localVPN.id;records.push(['vpns',localVPN]);}
    if(kind==='server'&&original.auth==='agent'&&original.shared.permissions.credentials)value.agentDelegate={owner:original.shared.owner,remoteId:original.shared.remoteId,source:original.shared.source};
    records.push([kind==='server'?'servers':'vpns',value]);
    const before=this.store.db.export(),Database=this.store.db.constructor;
    try{this.store.db.run('BEGIN');for(const [table,p]of records)this.store.db.run('INSERT INTO '+table+' VALUES (?,?)',[p.id,JSON.stringify(p)]);this.store.db.run('COMMIT');this.store.save();}catch(error){this.store.db.close();this.store.db=new Database(before);throw error;}
    this.changed();return kind==='server'?publicServer(value):publicVPN(value);
  }
  startCast(sessionId, keyId) {
    const key = this.rows('team_keys').find(k => k.id === keyId && !k.revoked);
    if (!this.listener || !key?.permissions.live) throw new Error('Choose an active key with read-only live viewing permission');
    const session = this.hooks.sessions?.().find(s => s.sessionId === sessionId); if (!session) throw new Error('Open a local SSH terminal first');
    if (this.casts.size >= 24) throw new Error('Maximum 24 terminal broadcasts');
    const existing = [...this.casts.values()].find(c => c.sessionId === sessionId && c.keyId === keyId); if (existing) return existing.id;
    const cast = { id: uid(), sessionId, keyId, name: session.name, cols: session.cols || 100, rows: session.rows || 30, chunks: [], bytes: 0,controllers:new Map() };
    this.casts.set(cast.id, cast); this.broadcastLists(); this.changed(); return cast.id;
  }
  stopCast(id) { const cast=this.casts.get(id);if(cast){cast.controllers.clear();for(const p of this.peers)if(p.keyId===cast.keyId)this.sendControl(p,id);}this.casts.delete(id); this.broadcastLists(); this.changed(); }
  sendControl(peer,castId) {
    const cast=this.casts.get(castId),key=this.rows('team_keys').find(k=>k.id===peer.keyId&&!k.revoked);
    const grantId=key?.permissions.live&&cast?.keyId===peer.keyId?cast.controllers.get(peer.id):null;
    if(!peer.socket.destroyed)peer.send({type:'cast-control',castId,canInput:!!grantId,grantId:grantId||null});
  }
  clearControl(peer) { for(const cast of this.casts.values())if(cast.controllers.delete(peer.id))this.sendControl(peer,cast.id); }
  setCollaboration(castId,peerId,enabled) {
    const cast=this.casts.get(castId),peer=[...this.peers].find(p=>p.id===peerId&&!p.socket.destroyed),key=this.rows('team_keys').find(k=>k.id===cast?.keyId&&!k.revoked);
    if(!cast||!peer||peer.keyId!==cast.keyId||!key?.permissions.live||!this.hooks.sessions?.().some(s=>s.sessionId===cast.sessionId))throw new Error('Live terminal or connected viewer is no longer available');
    if(enabled===true)cast.controllers.set(peer.id,uid());else cast.controllers.delete(peer.id);
    this.sendControl(peer,castId);this.store.audit('team.live.control',`${enabled===true?'granted':'revoked'}: ${peer.id} / ${castId}`);this.changed();
  }
  receiveCastInput(peer,message) {
    if(typeof message.data!=='string'||!message.data||Buffer.byteLength(message.data)>65536||typeof message.castId!=='string'||message.castId.length>80||typeof message.grantId!=='string'||message.grantId.length>80){peer.socket.destroy();return;}
    const cast=this.casts.get(message.castId),key=this.rows('team_keys').find(k=>k.id===peer.keyId&&!k.revoked);
    if(!cast||!key?.permissions.live||cast.keyId!==peer.keyId||peer.watching!==cast.id||cast.controllers.get(peer.id)!==message.grantId){this.sendControl(peer,message.castId);return;}
    if(!this.hooks.sessions?.().some(s=>s.sessionId===cast.sessionId)||!this.hooks.writeSession){this.stopCast(cast.id);return;}
    try{this.hooks.writeSession(cast.sessionId,message.data);}catch{this.stopCast(cast.id);}
  }
  sendCastList(peer) {
    const key = this.rows('team_keys').find(k => k.id === peer.keyId && !k.revoked);
    if (!key) return;
    peer.send({ type: 'casts', casts: key.permissions.live ? [...this.casts.values()].filter(c => c.keyId === peer.keyId).map(c => ({ id: c.id, name: c.name, cols: c.cols, rows: c.rows })) : [] });
    if (!key.permissions.live || !this.casts.has(peer.watching)) peer.watching = null;
  }
  broadcastLists() { for (const p of this.peers) if (p.keyId) this.sendCastList(p); }
  watch(peer, castId) {
    if (castId === null) { this.clearControl(peer);peer.watching = null;this.changed(); return; }
    const key = this.rows('team_keys').find(k => k.id === peer.keyId && !k.revoked), cast = this.casts.get(castId);
    if (!key?.permissions.live || !cast || cast.keyId !== key.id) { peer.socket.destroy(); return; }
    if(peer.watching&&peer.watching!==castId)this.clearControl(peer);peer.watching = castId;
    peer.send({ type: 'cast', castId, reset: true, data: cast.chunks.join(''), cols: cast.cols, rows: cast.rows });
    this.sendControl(peer,castId);this.changed();
  }
  watchClient(id, castId) { const link = this.links.get(id); if (link?.status !== 'connected') throw new Error('Sharing server is offline'); if(link.watching!==castId){if(link.watching)this.emit('team-cast-control',{clientId:id,castId:link.watching,canInput:false});link.controls.clear();}link.watching=castId;link.send({ type: 'watch', castId }); }
  writeLive(id,castId,data) { const link=this.links.get(id);if(link?.status!=='connected'||link.socket.destroyed||link.watching!==castId||!link.controls.has(castId))throw new Error('Operator has not granted collaboration');if(typeof data!=='string'||!data||Buffer.byteLength(data)>65536)throw new Error('Invalid live input');link.send({type:'cast-input',castId,grantId:link.controls.get(castId),data}); }
  terminal(event) {
    for (const cast of [...this.casts.values()].filter(c => c.sessionId === event.sessionId)) {
      if (event.closed) { this.stopCast(cast.id); continue; }
      if (event.cols) { cast.cols = event.cols; cast.rows = event.rows; }
      const data = event.data || ''; cast.chunks.push(data); cast.bytes += Buffer.byteLength(data);
      while (cast.bytes > 256 * 1024 && cast.chunks.length) cast.bytes -= Buffer.byteLength(cast.chunks.shift());
      for (const peer of this.peers) if (peer.keyId === cast.keyId && peer.watching === cast.id) {
        const key = this.rows('team_keys').find(k => k.id === peer.keyId && !k.revoked);
        if (key?.permissions.live) peer.send({ type: 'cast', castId: cast.id, data, cols: cast.cols, rows: cast.rows });
      }
    }
  }
  tick() {
    if (this.closed) return;
    for (const peer of this.peers) { if (Date.now() - peer.last > 45000) peer.socket.destroy(); else if (peer.keyId) this.syncPeer(peer); }
    for (const client of this.rows('team_clients').filter(c => c.enabled)) {
      const link = this.links.get(client.id);
      if (!link || ((!link.socket || link.socket.destroyed) && Date.now() > (link.retry || 0))) this.connectClient(client.id);
      else if (link.status === 'connected') { if (Date.now() - link.last > 45000) link.socket.destroy(); else if (Date.now() - link.lastPing > 10000) { link.lastPing = Date.now(); link.send({ type: 'ping' }); } }
    }
  }
  shutdown() { this.closed = true; clearInterval(this.timer); this.stop(); for (const link of this.links.values()) link.socket?.destroy(); }
}
module.exports = { Team, parseInvite };
