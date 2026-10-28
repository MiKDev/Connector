const {test}=require('node:test');
const assert=require('node:assert/strict');
const fs=require('node:fs'),os=require('node:os'),path=require('node:path'),net=require('node:net');
const {Store}=require('../electron/store.cjs');
const {NetworkConfig,normalizeVPN}=require('../electron/network-config.cjs');
const {Backups,encode,decode}=require('../electron/backups.cjs');
const {Routes,routeFor,matchesCIDR}=require('../electron/routes.cjs');
const {SSH}=require('../electron/ssh.cjs');
const {Service}=require('../electron/service.cjs');
const {Files}=require('../electron/files.cjs');
const {startServer}=require('./ssh-fixture.cjs');
const vault={available:()=>true,encrypt:s=>Buffer.from('sealed:'+s).toString('base64'),decrypt:s=>Buffer.from(s,'base64').toString().slice(7)};
const vpnInput={name:'VPN A',gateway:'vpn.example.invalid',username:'test-user',password:'vpn-password-fixture',psk:'psk-fixture',allowedCidrs:['10.77.0.0/24']};
async function setup(t){const dir=fs.mkdtempSync(path.join(os.tmpdir(),'connector-network-'));const store=await Store.open(dir,vault);const config=new NetworkConfig(store);t.after(()=>{store.db.close();fs.rmSync(dir,{recursive:true,force:true});});return{store,config,dir};}
function server(store,vpn,host='10.77.0.1'){return store.put({name:'Private '+vpn.name,host,port:22,username:'tester',auth:'password',secret:'test-password',routeMode:'vpn',vpnId:vpn.id});}
test('routing resolves explicit bindings, CIDR/domain/group policies, overlap ambiguity and fail-closed defaults',async t=>{
 const{store,config}=await setup(t),a=config.saveVPN(vpnInput),b=config.saveVPN({...vpnInput,name:'VPN B'}),s=server(store,a);
 assert.equal(routeFor(s,config).vpnId,a.id);
 config.saveRule({name:'network A',cidr:'10.77.0.0/24',action:'vpn',vpnId:a.id,priority:100});
 assert.equal(routeFor({...s,routeMode:'auto'},config).vpnId,a.id);
 config.saveRule({name:'network B',cidr:'10.77.0.0/24',action:'vpn',vpnId:b.id,priority:100});
 assert.throws(()=>routeFor({...s,routeMode:'auto'},config),/Ambiguous/);
 assert.equal(routeFor(s,config).vpnId,a.id,'explicit per-connection binding wins over ambiguous overlap');
 config.saveRule({name:'specific host B',cidr:'10.77.0.1/32',action:'vpn',vpnId:b.id,priority:100});
 assert.equal(routeFor({...s,routeMode:'auto'},config).vpnId,b.id);
 assert.throws(()=>routeFor({...s,host:'unmatched.internal.invalid',routeMode:'auto'},config),/no matching/);
 config.saveRule({name:'private DNS',domain:'internal.invalid',group:'Ungrouped',action:'vpn',vpnId:a.id,priority:20});
 assert.equal(routeFor({...s,host:'db.internal.invalid',routeMode:'auto'},config).vpnId,a.id);
 config.saveRule({name:'block',action:'block',serverId:s.id,priority:1});assert.throws(()=>routeFor({...s,routeMode:'auto'},config),/blocked/);
 assert.equal(matchesCIDR('::ffff:10.77.0.2','10.77.0.0/24'),true);assert.equal(matchesCIDR('2001:db8::1','2001:db8::/32'),true);
 assert.throws(()=>normalizeVPN({...vpnInput,dns:['not-an-ip']}),/DNS/);
 assert.equal(normalizeVPN({...vpnInput,allowedCidrs:['10.77.0.15/24']}).allowedCidrs[0],'10.77.0.0/24');
});
test('portable encrypted backup remaps dependencies, refuses tampering, keeps originals and disables imported policies',async t=>{
 const{store,config}=await setup(t),vpn=config.saveVPN(vpnInput),saved=server(store,vpn);config.saveRule({name:'linked',action:'vpn',vpnId:vpn.id,serverId:saved.id});
 const backups=new Backups(store,config),plain=await backups.export({servers:true,vpns:true});
 assert.ok(!plain.includes('test-password'));assert.ok(!plain.includes('vpn-password-fixture'));assert.ok(!plain.includes('psk-fixture'));
 const pass='independent backup phrase';const encrypted=await backups.export({servers:true,vpns:true,includeSecrets:true,passphrase:pass});
 assert.ok(!encrypted.includes('test-password'));assert.ok(!encrypted.includes('vpn-password-fixture'));
 await assert.rejects(()=>decode(encrypted,'incorrect passphrase!'),/Incorrect/);
 const tampered=JSON.parse(encrypted);tampered.ciphertext=Buffer.alloc(40,1).toString('base64');await assert.rejects(()=>decode(JSON.stringify(tampered),pass),/tampered/);
 const decoded=await decode(encrypted,pass),result=backups.import(decoded);
 assert.equal(store.all().length,2);assert.equal(config.vpns().length,2);assert.equal(result.servers.length,1);
 const imported=store.get(result.servers[0].id);assert.notEqual(imported.id,saved.id);assert.notEqual(imported.vpnId,vpn.id);assert.equal(vault.decrypt(imported.secret),'test-password');assert.equal(vault.decrypt(config.get(imported.vpnId).pskSecret),'psk-fixture');
 assert.equal(config.rules().find(r=>r.serverId===imported.id).enabled,false);
 assert.equal(store.get(saved.id).vpnId,vpn.id);
 const metadata=await decode(plain);const result2=backups.import(metadata);assert.equal(result2.servers[0].hasSecret,false);
 const bad=JSON.parse(plain);bad.servers[0].credential='plaintext-password';await assert.rejects(()=>decode(JSON.stringify(bad)),/Unencrypted/);
 const before=store.all().length,invalid=structuredClone(decoded);invalid.servers[0].vpnId='missing';assert.throws(()=>backups.import(invalid),/missing/);assert.equal(store.all().length,before);
 const oldSave=store.save.bind(store);store.save=()=>{throw new Error('simulated disk error');};assert.throws(()=>backups.import(decoded),/disk error/);store.save=oldSave;assert.equal(store.all().length,before,'failed save restores database atomically');
 await assert.rejects(()=>encode(decoded,'short'),/passphrase/);
});
async function socks(targetPort){
 const clients=new Set(),requests=[];const listener=net.createServer(client=>{clients.add(client);client.on('close',()=>clients.delete(client));client.on('error',()=>{});let buffer=Buffer.alloc(0),stage=0,upstream;
 const consume=data=>{buffer=Buffer.concat([buffer,data]);while(true){
  if(stage===0){if(buffer.length<2||buffer.length<2+buffer[1])return;buffer=buffer.subarray(2+buffer[1]);stage=1;client.write(Buffer.from([5,2]));}
  else if(stage===1){if(buffer.length<2)return;const ul=buffer[1];if(buffer.length<3+ul)return;const pl=buffer[2+ul];if(buffer.length<3+ul+pl)return;const user=buffer.subarray(2,2+ul).toString(),pass=buffer.subarray(3+ul,3+ul+pl).toString();if(user!=='fixture'||pass!=='proxy-secret'){client.destroy();return;}buffer=buffer.subarray(3+ul+pl);stage=2;client.write(Buffer.from([1,0]));}
  else if(stage===2){if(buffer.length<5)return;const at=buffer[3],size=at===1?4:at===4?16:buffer[4],offset=at===3?5:4;if(buffer.length<offset+size+2)return;const host=at===3?buffer.subarray(offset,offset+size).toString():[...buffer.subarray(offset,offset+size)].join('.');requests.push({host,port:buffer.readUInt16BE(offset+size)});buffer=buffer.subarray(offset+size+2);stage=3;client.off('data',consume);upstream=net.createConnection(targetPort,'127.0.0.1',()=>{client.write(Buffer.from([5,0,0,1,127,0,0,1,0,0]));if(buffer.length)upstream.write(buffer);client.pipe(upstream);upstream.pipe(client);});upstream.on('error',()=>client.destroy());client.on('close',()=>upstream.destroy());return;}
  else return;
 }};client.on('data',consume);});await new Promise(r=>listener.listen(0,'127.0.0.1',r));return{proxy:{port:listener.address().port,username:'fixture',password:'proxy-secret'},requests,close:async()=>{clients.forEach(c=>c.destroy());await new Promise(r=>listener.close(r));}};
}
test('SSH across independent authenticated gateways keeps overlapping hosts and DNS names separate with route-scoped host trust',async t=>{
 const{store,config,dir}=await setup(t);const rootA=path.join(dir,'peer-A'),rootB=path.join(dir,'peer-B');fs.mkdirSync(rootA);fs.mkdirSync(rootB);fs.writeFileSync(path.join(rootA,'network-A.txt'),'A');fs.writeFileSync(path.join(rootB,'network-B.txt'),'B');
 const peerA=await startServer(undefined,{root:rootA}),peerB=await startServer(undefined,{root:rootB}),proxyA=await socks(peerA.port),proxyB=await socks(peerB.port);
 const a=config.saveVPN(vpnInput),b=config.saveVPN({...vpnInput,name:'VPN B'}),sa=server(store,a,'db.private.invalid'),sb=server(store,b,'db.private.invalid');let approvals=0;
 const gateways={ensure:async id=>id===a.id?proxyA.proxy:proxyB.proxy,track:()=>{},shutdown:()=>{}};const routes=new Routes(config,gateways);const ssh=new SSH(store,vault,async()=>{approvals++;return true;},()=>{},routes);
 t.after(async()=>{ssh.closeAll();routes.shutdown();await proxyA.close();await proxyB.close();await peerA.close();await peerB.close();});
 const sessions=await Promise.all([ssh.open(sa.id),ssh.open(sb.id)]);assert.equal(sessions.length,2);assert.equal(approvals,2);assert.equal(proxyA.requests[0].host,'db.private.invalid');assert.equal(proxyB.requests[0].host,'db.private.invalid');
 assert.ok(store.fingerprint('vpn:'+a.id+'/[db.private.invalid]:22'));assert.ok(store.fingerprint('vpn:'+b.id+'/[db.private.invalid]:22'));assert.equal(store.fingerprint('[db.private.invalid]:22'),undefined);
 const files=new Files(store,ssh,vault,()=>{});t.after(()=>files.shutdown());const endpointA=await files.open(sa.id),endpointB=await files.open(sb.id);
 assert.ok((await files.listing(endpointA.id,endpointA.home)).entries.some(e=>e.name==='network-A.txt'));
 assert.ok((await files.listing(endpointB.id,endpointB.home)).entries.some(e=>e.name==='network-B.txt'));
 const service=new Service(store,ssh,()=>{});service.setAI(true);const request=service.request('execution',{command:'uptime',serverIds:[sa.id]});config.saveVPN({...vpnInput,name:'Changed VPN'},a.id);await assert.rejects(()=>service.decide(request.id,true),/route changed/);
 gateways.ensure=async()=>{throw new Error('VPN unavailable');};await assert.rejects(()=>routes.dial(store.get(sa.id)),/VPN unavailable/);
});
test('queued execution targets cannot move to a changed VPN policy after approval',async t=>{
 const{store}=await setup(t);const ids=Array.from({length:6},(_,i)=>store.put({name:'Queued '+i,host:'127.0.0.1',username:'test',auth:'agent'}).id);
 let policy='approved',started=0;const pending=[];
 const ssh={securitySnapshot:s=>require('../electron/core.cjs').snapshot({s,policy}),exec:async()=>{started++;return new Promise(resolve=>pending.push(()=>resolve({status:'succeeded',exitCode:0})));}};
 const service=new Service(store,ssh,()=>{}),view=service.run({serverIds:ids,command:'uptime'});assert.equal(started,4);policy='changed';pending.forEach(resolve=>resolve());
 for(let i=0;i<100&&service.jobs.get(view.id).status==='running';i++)await new Promise(r=>setTimeout(r,5));
 const job=service.jobs.get(view.id);assert.equal(job.status,'completed');assert.equal(started,4);assert.ok(job.results.slice(4).every(r=>r.status==='failed'&&r.error.includes('route changed')));
});
