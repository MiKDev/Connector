const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { Store } = require('../electron/store.cjs');
const { NetworkConfig } = require('../electron/network-config.cjs');
const { Team, parseInvite } = require('../electron/team.cjs');
const { channel, connect } = require('../electron/team-transport.cjs');
const { Backups } = require('../electron/backups.cjs');
const { SSH } = require('../electron/ssh.cjs');
const { parseDistro } = require('../electron/distro.cjs');
const { startServer } = require('./ssh-fixture.cjs');
const vault = { available:()=>true, encrypt:s=>Buffer.from(s).toString('base64'), decrypt:s=>Buffer.from(s,'base64').toString() };
const pause = ms => new Promise(r=>setTimeout(r,ms));
async function until(check, message='Condition timed out') { for(let i=0;i<150;i++){if(await check())return;await pause(40);}throw new Error(message); }
async function setup(t, hooks={}) { const dir=fs.mkdtempSync(path.join(os.tmpdir(),'connector-team-'));const store=await Store.open(dir,vault),network=new NetworkConfig(store),events=[];const team=new Team(store,network,{...hooks,emit:(type,data)=>events.push({type,...data})});t.after(()=>{team.shutdown();store.db.close();fs.rmSync(dir,{recursive:true,force:true});});return {store,network,team,events}; }
const profile = (name='Alpha')=>({name,host:'127.0.0.1',username:'tester',group:'Team',auth:'password',secret:'fixture-password',routeMode:'direct'});
const permissions={terminal:true,exec:false,files:false,credentials:true,live:true};
test('Live collaboration is per connected peer and cast; stale, revoked and reconnect input stays blocked',async t=>{
 const writes=[],sessions=[{sessionId:'one',name:'One'},{sessionId:'two',name:'Two'}];
 const owner=await setup(t,{sessions:()=>sessions,writeSession:(id,data)=>writes.push({id,data})}),a=await setup(t),b=await setup(t),other=await setup(t);
 await start(owner.team);const invitation=invite(owner.team,[]),keyId=parseInvite(invitation).id;
 const aid=await a.team.addClient({name:'Owner',viewerName:'Alice',invitation}),bid=await b.team.addClient({name:'Owner',viewerName:'Bob',invitation});
 const second=invite(owner.team,[],[],'Other key'),oid=await other.team.addClient({name:'Owner',viewerName:'Other',invitation:second});
 await until(()=>[a.team.links.get(aid),b.team.links.get(bid),other.team.links.get(oid)].every(l=>l?.status==='connected'));
 const first=owner.team.startCast('one',keyId),next=owner.team.startCast('two',keyId),alice=()=>[...owner.team.peers].find(p=>p.name==='Alice'),bob=[...owner.team.peers].find(p=>p.name==='Bob'),outsider=[...owner.team.peers].find(p=>p.name==='Other');
 a.team.watchClient(aid,first);b.team.watchClient(bid,first);await until(()=>alice().watching===first&&bob.watching===first);
 assert.throws(()=>a.team.writeLive(aid,first,'blocked'),/not granted/);assert.throws(()=>owner.team.setCollaboration(first,outsider.id,true),/no longer/);
 owner.team.setCollaboration(first,alice().id,true);await until(()=>a.team.links.get(aid).controls.has(first));const oldGrant=a.team.links.get(aid).controls.get(first);
 a.team.writeLive(aid,first,'echo accepted\r');await until(()=>writes.length===1);assert.deepEqual(writes[0],{id:'one',data:'echo accepted\r'});assert.throws(()=>b.team.writeLive(bid,first,'blocked'),/not granted/);
 b.team.links.get(bid).send({type:'cast-input',castId:first,grantId:oldGrant,data:'stolen grant'});
 a.team.links.get(aid).send({type:'cast-input',castId:next,grantId:oldGrant,data:'wrong terminal'});await pause(80);assert.equal(writes.length,1);
 owner.team.setCollaboration(first,alice().id,false);owner.team.setCollaboration(first,alice().id,true);await until(()=>a.team.links.get(aid).controls.get(first)!==oldGrant);
 a.team.links.get(aid).send({type:'cast-input',castId:first,grantId:oldGrant,data:'queued stale'});await pause(80);assert.equal(writes.length,1);
 owner.team.setCollaboration(first,alice().id,false);await until(()=>!a.team.links.get(aid).controls.has(first));assert.throws(()=>a.team.writeLive(aid,first,'revoked'),/not granted/);
 owner.team.setCollaboration(first,alice().id,true);a.team.watchClient(aid,null);await until(()=>!owner.team.casts.get(first).controllers.size);
 a.team.watchClient(aid,first);await until(()=>alice().watching===first);owner.team.setCollaboration(first,alice().id,true);
 const oldPeer=alice().id;a.team.links.get(aid).socket.destroy();await until(()=>!owner.team.casts.get(first).controllers.size);a.team.connectClient(aid);await until(()=>a.team.links.get(aid).status==='connected');assert.notEqual(alice().id,oldPeer);assert.equal(a.team.links.get(aid).controls.size,0);
 a.team.watchClient(aid,first);await until(()=>alice().watching===first);owner.team.setCollaboration(first,alice().id,true);await until(()=>a.team.links.get(aid).controls.has(first));
 const key=owner.team.state().keys.find(k=>k.id===keyId);owner.team.updateKey(keyId,key);await until(()=>!a.team.links.get(aid).controls.has(first));
 owner.team.setCollaboration(first,alice().id,true);owner.team.stopCast(first);await until(()=>!a.team.links.get(aid).controls.has(first));
 a.team.watchClient(aid,next);await until(()=>alice().watching===next);owner.team.setCollaboration(next,alice().id,true);owner.team.terminal({sessionId:'two',closed:true});await until(()=>!a.team.links.get(aid).controls.has(next));assert.ok(!owner.team.casts.has(next));
 const last=owner.team.startCast('one',keyId);a.team.watchClient(aid,last);await until(()=>alice().watching===last);owner.team.setCollaboration(last,alice().id,true);owner.team.revoke(keyId);await until(()=>a.team.links.get(aid).status==='revoked');assert.throws(()=>a.team.writeLive(aid,last,'after key revoke'),/not granted/);
 assert.equal(writes.length,1);assert.equal(other.team.links.get(oid).status,'connected');
});
async function start(team){await team.start({host:'127.0.0.1',port:0});}
function invite(team,s,v=[],name='Operator key',perms=permissions){return team.createKey({name,advertiseHost:'127.0.0.1',serverIds:s,vpnIds:v,permissions:perms}).invitation;}

test('TLS sharing: scoped keys, multiple owners, versions, dependencies, live read-only protocol, revoke/delete and restart',async t=>{
  const invalidated=[];const owner=await setup(t),other=await setup(t),client=await setup(t,{invalidateServer:id=>invalidated.push(id)});
  await start(owner.team);await start(other.team);
  const vpn=owner.network.saveVPN({name:'Private VPN',gateway:'vpn.invalid',username:'u',password:'vpn-test',psk:'psk-test'});
  const a=owner.store.put({...profile(),routeMode:'vpn',vpnId:vpn.id}),hidden=owner.store.put(profile('Not shared'));
  const b=other.store.put(profile('Other owner'));
  const invitation=invite(owner.team,[a.id],[vpn.id]);const parsed=parseInvite(invitation);
  const ca=await client.team.addClient({name:'Owner A',invitation});
  const cb=await client.team.addClient({name:'Owner B',invitation:invite(other.team,[b.id])});
  await until(()=>client.team.state().clients.every(c=>c.status==='connected'));
  assert.equal(client.store.all().length,2);assert.ok(!client.store.all().some(s=>s.name===hidden.name));
  let local=client.store.all(true).find(s=>s.shared.owner===ca),localVPN=client.network.vpns(true)[0];
  assert.equal(local.vpnId,localVPN.id);assert.equal(vault.decrypt(local.secret),'fixture-password');assert.equal(vault.decrypt(localVPN.passwordSecret),'vpn-test');assert.equal(vault.decrypt(localVPN.pskSecret),'psk-test');
  assert.equal(local.shared.version,1);client.team.assert(local,'terminal');assert.throws(()=>client.team.assert(local,'exec'),/does not allow/);
  assert.throws(()=>client.store.put({...local,name:'Escape'},local.id),/managed/);assert.throws(()=>client.store.duplicate(local.id),/cannot be copied/);assert.throws(()=>client.network.duplicate(localVPN.id),/cannot be copied/);
  const backup=await new Backups(client.store,client.network).export({servers:true,vpns:true});assert.equal(JSON.parse(backup).servers.length,0);assert.equal(JSON.parse(backup).vpns.length,0);
  owner.store.put({...profile('Updated Alpha'),routeMode:'vpn',vpnId:vpn.id},a.id);
  for(const p of owner.team.peers)owner.team.syncPeer(p);
  await until(()=>client.store.all().some(s=>s.name==='Updated Alpha'));
  local=client.store.get(local.id);assert.equal(local.shared.version,2);assert.ok(invalidated.includes(local.id));
  const unchanged=JSON.stringify(local);for(const p of owner.team.peers)owner.team.syncPeer(p);await pause(100);assert.equal(JSON.stringify(client.store.get(local.id)),unchanged,'unchanged sync does not rewrite encrypted credentials or timestamps');
  owner.network.saveVPN({...owner.network.get(vpn.id),password:'updated-vpn-password'},vpn.id);
  for(const p of owner.team.peers)owner.team.syncPeer(p);
  await until(()=>client.network.vpns(true)[0].shared.version===2);
  assert.equal(vault.decrypt(client.network.vpns(true)[0].passwordSecret),'updated-vpn-password');
  owner.team.updateKey(parsed.id,{name:'Updated access',serverIds:[a.id],vpnIds:[vpn.id],permissions:{...permissions,files:true}});
  await until(()=>client.store.get(local.id).shared.keyRevision===2);client.team.assert(client.store.get(local.id),'files');
  owner.team.hooks.sessions=()=>[{sessionId:'terminal-A',name:'Operator terminal',cols:100,rows:20}];
  const cast=owner.team.startCast('terminal-A',parsed.id);
  await until(()=>client.team.state().clients.find(c=>c.id===ca).casts.length===1);
  client.team.watchClient(ca,cast);await until(()=>client.events.some(e=>e.type==='team-cast'&&e.reset));
  owner.team.terminal({sessionId:'terminal-A',data:'\x1b[32mLIVE output\x1b[0m\r\n'});
  await until(()=>client.events.some(e=>e.type==='team-cast'&&e.data?.includes('LIVE output')));
  // Malicious viewer tries an input message over its authenticated TLS socket.
  client.team.links.get(ca).send({type:'input',castId:cast,data:'touch /tmp/unauthorized\n'});
  await until(()=>client.team.links.get(ca).socket.destroyed);assert.throws(()=>client.team.assert(local,'terminal'),/online/);
  client.team.connectClient(ca);await until(()=>client.team.links.get(ca).status==='connected');
  const second=invite(owner.team,[a.id],[vpn.id],'Second key');const secondId=parseInvite(second).id;
  await client.team.addClient({name:'Owner A second key',invitation:second});
  await until(()=>client.store.all().length===3);
  owner.team.revoke(parsed.id);await until(()=>!client.store.all().some(s=>s.shared.owner===ca));
  assert.ok(client.store.all().some(s=>s.shared.owner===cb),'other owner unaffected');assert.ok(client.store.all().some(s=>s.shared.source==='Owner A second key'),'other key unaffected');
  owner.team.revoke(secondId,true);await until(()=>client.store.all().length===1);
  assert.ok(!owner.team.rows('team_keys').some(k=>k.id===secondId));
  const identityBefore=owner.team.identity().fingerprint;owner.team.stop();await start(owner.team);assert.equal(owner.team.identity().fingerprint,identityBefore,'identity persists across listener restart');
  assert.ok(!JSON.stringify(owner.team.state()).includes(parsed.token));assert.ok(!fs.readFileSync(owner.store.filename).includes(Buffer.from(parsed.token)),'server stores token hash only');
});

test('sharing refuses wrong certificate pin, invalid bearer token, malformed invitations and unsafe profile selection',async t=>{
  const owner=await setup(t),client=await setup(t);await start(owner.team);const s=owner.store.put(profile());const invitation=invite(owner.team,[s.id]);const parsed=parseInvite(invitation);
  const badPin=connect({...parsed,fingerprint:'0'.repeat(64)});await assert.rejects(badPin.ready,/identity/);
  const wrongToken=connect(parsed);await wrongToken.ready;let reply;const send=channel(wrongToken.socket,m=>reply=m);send({type:'auth',protocol:1,id:parsed.id,token:'wrong'});await until(()=>reply);assert.equal(reply.type,'denied');wrongToken.socket.destroy();
  assert.throws(()=>parseInvite('not a key'),/Invalid/);
  const auto=owner.store.put({...profile('Automatic'),routeMode:'auto'});assert.throws(()=>invite(owner.team,[auto.id]),/specific VPN/);
  const privateKey=owner.store.put({...profile('Local key'),auth:'key',keyPath:'/local/key'});assert.throws(()=>invite(owner.team,[privateKey.id]),/ENOENT/);
  const noSecrets=invite(owner.team,[s.id],[],'Metadata',{terminal:true,live:false});await client.team.addClient({name:'Metadata',invitation:noSecrets});await until(()=>client.store.all().length===1);assert.ok(!client.store.all()[0].hasSecret);
  assert.equal(client.store.all()[0].shared.permissions.live,false);
});

test('shared SSH sessions close on key revocation; feature permissions enforced at transport',async t=>{
  const fixture=await startServer();t.after(()=>fixture.close());const owner=await setup(t);let ssh;const client=await setup(t,{invalidateServer:id=>ssh?.closeServer(id)});await start(owner.team);
  const p=owner.store.put({...profile('Real shared SSH'),port:fixture.port,secret:'test-password'});
  ssh=new SSH(client.store,vault,async()=>true,()=>{});ssh.authorize=(p,c)=>client.team.assert(p,c);t.after(()=>ssh.closeAll());
  const invitation=invite(owner.team,[p.id]);const cid=await client.team.addClient({name:'SSH owner',invitation});await until(()=>client.team.links.get(cid)?.status==='connected');
  const local=client.store.all()[0];const session=await ssh.open(local.id);assert.ok(ssh.sessions.has(session.sessionId));
  await assert.rejects(ssh.connect(client.store.get(local.id),null,{capability:'files'}),/does not allow files/);
  owner.team.revoke(parseInvite(invitation).id,true);await until(()=>ssh.sessions.size===0);await assert.rejects(ssh.open(local.id),/no longer exists/);
});

test('copy operations preserve local encrypted credentials and allocate IDs; distro parser never evaluates shell output',async t=>{
  const {store,network}=await setup(t);const s=store.put(profile());const copy=store.duplicate(s.id);assert.notEqual(copy.id,s.id);assert.equal(store.get(copy.id).secret,store.get(s.id).secret);
  const vpn=network.saveVPN({name:'VPN',gateway:'vpn.invalid',username:'u',password:'v',psk:'p'}),v=network.duplicate(vpn.id);assert.notEqual(v.id,vpn.id);assert.equal(network.get(v.id).pskSecret,network.get(vpn.id).pskSecret);
  assert.equal(parseDistro('ID=ubuntu\nID_LIKE=debian\n'),'ubuntu');assert.equal(parseDistro('ID="opensuse-leap"\n'),'opensuse');assert.equal(parseDistro('ID=custom\nID_LIKE="rhel fedora"\n'),'rhel');assert.equal(parseDistro('ID=$(touch /tmp/no)\n'),'linux');assert.equal(parseDistro('unsupported output'),null);
});

test('listener start is serialized and stopping closes incomplete unauthenticated handshakes',async t=>{
  const {team}=await setup(t);const pending=team.start({host:'127.0.0.1',port:0});await assert.rejects(team.start({host:'127.0.0.1',port:0}),/starting/);await pending;
  const raw=require('node:net').connect(team.state().server.port,'127.0.0.1');raw.on('error',()=>{});let closed=false;raw.on('close',()=>closed=true);await until(()=>team.rawSockets.size===1);team.stop();await until(()=>closed);assert.equal(team.rawSockets.size,0);assert.equal(team.state().server.listening,false);
});

test('shared encrypted private keys authenticate, track file revisions and persist independently with VPN dependencies and backups',async t=>{
  const {utils}=require('ssh2');const passphrase='fixture-key-passphrase';
  const pair=utils.generateKeyPairSync('ed25519',{passphrase,cipher:'aes256-ctr'});
  const fixture=await startServer(undefined,{publicKey:pair.public});t.after(()=>fixture.close());
  const owner=await setup(t),client=await setup(t);await start(owner.team);
  const file=path.join(path.dirname(owner.store.filename),'fixture-key');fs.writeFileSync(file,pair.private);
  const source=owner.store.put({...profile('Key SSH'),auth:'key',port:fixture.port,keyPath:file,secret:passphrase});
  const vpn=owner.network.saveVPN({name:'VPN to save',gateway:'vpn.invalid',username:'u',password:'pw',psk:'psk'});
  const viaVPN=owner.store.put({...profile('Connection with VPN'),routeMode:'vpn',vpnId:vpn.id});
  const invitation=invite(owner.team,[source.id,viaVPN.id],[vpn.id]),cid=await client.team.addClient({name:'Key owner',invitation});
  await until(()=>client.team.links.get(cid)?.status==='connected');
  const shared=client.store.all(true).find(s=>s.name==='Key SSH');assert.equal(shared.keyPath,'');assert.equal(shared.keySource,'vault');assert.equal(vault.decrypt(shared.privateKeySecret),pair.private);assert.equal(vault.decrypt(shared.secret),passphrase);
  assert.ok(!JSON.stringify(client.store.all()).includes('PRIVATE KEY'));assert.ok(!('privateKeySecret' in client.store.all().find(s=>s.id===shared.id)));
  const ssh=new SSH(client.store,vault,async()=>true,()=>{});ssh.authorize=(p,c)=>client.team.assert(p,c);t.after(()=>ssh.closeAll());
  const opened=await ssh.open(shared.id);assert.ok(ssh.sessions.has(opened.sessionId));ssh.close(opened.sessionId);
  const saved=client.team.persist('server',shared.id);assert.ok(!saved.shared);assert.equal(saved.auth,'key');
  const withVPN=client.team.persist('server',client.store.all().find(s=>s.name==='Connection with VPN').id);assert.ok(!client.network.get(withVPN.vpnId).shared);assert.equal(vault.decrypt(client.network.get(withVPN.vpnId).passwordSecret),'pw');
  const keyWithoutSecrets=invite(owner.team,[source.id],[],'Key metadata',{terminal:true});const version1=owner.team.manifest(owner.team.rows('team_keys').find(k=>k.id===parseInvite(invitation).id)).servers.find(s=>s.id===source.id).version;
  owner.team.manifest(owner.team.rows('team_keys').find(k=>k.id===parseInvite(keyWithoutSecrets).id));
  assert.equal(owner.team.manifest(owner.team.rows('team_keys').find(k=>k.id===parseInvite(invitation).id)).servers.find(s=>s.id===source.id).version,version1,'different secret grants cannot churn one profile version');
  const replacement=utils.generateKeyPairSync('ed25519',{passphrase,cipher:'aes256-ctr'});fs.writeFileSync(file,replacement.private);for(const p of owner.team.peers)owner.team.syncPeer(p);
  await until(()=>client.store.get(shared.id).shared.version===version1+1);assert.equal(vault.decrypt(client.store.get(shared.id).privateKeySecret),replacement.private);assert.equal(vault.decrypt(client.store.get(saved.id).privateKeySecret),pair.private,'saved key does not follow source updates');
  owner.team.revoke(parseInvite(invitation).id,true);await until(()=>!client.store.all().some(s=>s.shared));
  const localSession=await ssh.open(saved.id);assert.ok(ssh.sessions.has(localSession.sessionId),'saved private key still works after revocation');
  const backups=new Backups(client.store,client.network);const plain=await backups.export({servers:true,vpns:true});assert.ok(!plain.includes('privateKeySecret'));assert.ok(!plain.includes('PRIVATE KEY'));
  const pass='portable-test-passphrase',encoded=await backups.export({servers:true,vpns:true,includeSecrets:true,passphrase:pass});const decoded=await require('../electron/backups.cjs').decode(encoded,pass);assert.equal(decoded.servers.find(s=>s.id===saved.id).privateKey,pair.private);
  const imported=await setup(t);new Backups(imported.store,imported.network).import(decoded);assert.equal(vault.decrypt(imported.store.all(true).find(s=>s.auth==='key').privateKeySecret),pair.private);
});

test('delegated SSH agent authenticates over TLS, rejects arbitrary signing and remains revocable after profile persistence',async t=>{
  const {utils}=require('ssh2');const parsed=utils.parseKey(utils.generateKeyPairSync('ed25519').private);let signed=0;
  const fixture=await startServer(undefined,{publicKey:parsed.getPublicSSH()});t.after(()=>fixture.close());
  const fakeAgent={getIdentities:cb=>cb(null,[parsed]),sign:(key,data,options,cb)=>{signed++;cb(null,parsed.sign(data,options?.hash));}};
  const owner=await setup(t,{agent:()=>fakeAgent});let ssh;const client=await setup(t,{invalidateServer:id=>ssh?.closeServer(id)});await start(owner.team);
  const source=owner.store.put({...profile('Owner agent'),auth:'agent',port:fixture.port});
  const invitation=invite(owner.team,[source.id]),cid=await client.team.addClient({name:'Agent owner',invitation});await until(()=>client.team.links.get(cid)?.status==='connected');
  const shared=client.store.all(true)[0];ssh=new SSH(client.store,vault,async()=>true,()=>{});ssh.authorize=(p,c)=>client.team.assert(p,c);ssh.sharedAgent=p=>client.team.agentFor(p);t.after(()=>ssh.closeAll());
  const session=await ssh.open(shared.id);assert.ok(ssh.sessions.has(session.sessionId));assert.ok(signed>0);
  const saved=client.team.persist('server',shared.id);assert.ok(saved.agentDelegate);assert.ok(!saved.shared);
  const savedSession=await ssh.open(saved.id);assert.ok(ssh.sessions.has(savedSession.sessionId));
  const before=signed;await assert.rejects(client.team.requestAgent(cid,source.id,{operation:'sign',publicKey:parsed.getPublicSSH().toString('base64'),data:Buffer.from('not SSH authentication').toString('base64')}),/refused/);assert.equal(signed,before,'generic signing never reaches the native agent');
  owner.team.revoke(parseInvite(invitation).id);await until(()=>ssh.sessions.size===0);assert.ok(client.store.get(saved.id));await assert.rejects(ssh.open(saved.id),/no longer available/);
});
