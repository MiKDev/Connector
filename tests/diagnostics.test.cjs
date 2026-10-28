const test=require('node:test'),assert=require('node:assert/strict'),net=require('node:net'),dgram=require('node:dgram');
const {Diagnostics,Telnet}=require('../electron/diagnostics.cjs');const {Routes}=require('../electron/routes.cjs');
const {startDNS}=require('./dns-fixture.cjs');const {plan,parse,resolver}=require('../electron/dns-tools.cjs');
const pause=ms=>new Promise(r=>setTimeout(r,ms));async function until(f){for(let i=0;i<200;i++){if(f())return;await pause(20);}throw new Error('Tool condition timed out');}
function setup(t,routes=new Routes({},{})){const events=[],tools=new Diagnostics(routes,{get:()=>({id:'vpn-fixture',name:'Private'})},(type,e)=>events.push({type,...e}));t.after(()=>tools.shutdown());return{tools,events};}
test('Telnet fragmented option negotiation, escaped IAC, terminal type and CRLF',()=>{
 const sent=[],telnet=new Telnet(b=>sent.push([...b]));assert.deepEqual([...telnet.receive(Buffer.from([255,251]))],[]);assert.equal(telnet.receive(Buffer.from([1,65,255,255,66])).toString('hex'),'41ff42');assert.deepEqual(sent[0],[255,253,1]);
 telnet.receive(Buffer.from([255,253,24,255,250,24,1,255]));telnet.receive(Buffer.from([240]));assert.ok(Buffer.from(sent.at(-1)).includes(Buffer.from('xterm-256color')));
 telnet.receive(Buffer.from([255,253,99]));assert.deepEqual(sent.at(-1),[255,252,99]);assert.equal(Buffer.from(telnet.encode('x\ry\nz\r\n')).toString(),'x\r\ny\r\nz\r\n');
});
test('Netcat TCP binary transfer, port probe, refused destination and stop pending listen',async t=>{
 const server=net.createServer(s=>s.pipe(s));await new Promise(r=>server.listen(0,'127.0.0.1',r));t.after(()=>server.close());const{tools,events}=setup(t);
 const job=tools.start({kind:'netcat',host:'127.0.0.1',port:server.address().port});await until(()=>events.some(e=>e.id===job.id&&e.status==='connected'));tools.write(job.id,'00 ff 41 0d 0a','hex');await until(()=>events.some(e=>e.id===job.id&&e.hex==='00ff410d0a'));assert.throws(()=>tools.write(job.id,'x','hex'),/Invalid payload/);tools.stop(job.id);assert.ok(!tools.jobs.has(job.id));
 const probe=tools.start({kind:'netcat',mode:'probe',host:'127.0.0.1',port:server.address().port});await until(()=>events.some(e=>e.id===probe.id&&e.closed));assert.ok(events.some(e=>e.id===probe.id&&e.data?.includes('is open')));
 const listener=tools.start({kind:'netcat',mode:'listen',host:'127.0.0.1',port:0});await until(()=>events.some(e=>e.id===listener.id&&e.status==='listening'));const port=events.find(e=>e.id===listener.id&&e.port).port;tools.stop(listener.id);
 const failed=tools.start({kind:'netcat',host:'127.0.0.1',port});await until(()=>events.some(e=>e.id===failed.id&&e.error));assert.equal(tools.jobs.size,0);
});
test('Netcat TCP listener accepts one peer and UDP binary send/reply',async t=>{
 const{tools,events}=setup(t);const listener=tools.start({kind:'netcat',mode:'listen',host:'127.0.0.1',port:0});await until(()=>events.some(e=>e.id===listener.id&&e.status==='listening'));const port=events.find(e=>e.id===listener.id&&e.port).port,socket=net.connect(port,'127.0.0.1');t.after(()=>socket.destroy());await until(()=>events.some(e=>e.id===listener.id&&e.status==='connected'));socket.write('tcp-listener');await until(()=>events.some(e=>e.data==='tcp-listener'));const reply=new Promise(r=>socket.once('data',r));tools.write(listener.id,'reply');assert.equal((await reply).toString(),'reply');tools.stop(listener.id);
 const udp=dgram.createSocket('udp4');udp.on('message',(b,r)=>udp.send(b,r.port,r.address));await new Promise(r=>udp.bind(0,'127.0.0.1',r));t.after(()=>udp.close());const client=tools.start({kind:'netcat',transport:'udp',host:'127.0.0.1',port:udp.address().port});await until(()=>events.some(e=>e.id===client.id&&e.status==='connected'));tools.write(client.id,'00ff01','hex');await until(()=>events.some(e=>e.id===client.id&&e.hex==='00ff01'));tools.stop(client.id);
 const receiver=tools.start({kind:'netcat',transport:'udp',mode:'listen',host:'127.0.0.1',port:0});await until(()=>events.some(e=>e.id===receiver.id&&e.port));const bind=events.find(e=>e.id===receiver.id&&e.port).port;udp.send(Buffer.from('udp-listen'),bind,'127.0.0.1');await until(()=>events.some(e=>e.id===receiver.id&&e.data==='udp-listen'));tools.write(receiver.id,'udp-reply');await until(()=>events.some(e=>e.id===receiver.id&&e.data==='udp-reply'));tools.stop(receiver.id);
});
test('Diagnostics validates input and uses isolated VPN TCP dial without direct fallback',async t=>{
 const calls=[];const{tools,events}=setup(t,{dial:async(p,signal)=>{calls.push(p);throw new Error('VPN intentionally unavailable');}});
 assert.throws(()=>tools.start({kind:'netcat',host:'--bad',port:80}),/Invalid/);assert.throws(()=>tools.start({kind:'traceroute',host:'127.0.0.1',vpnId:'v'}),/VPN routing/);assert.throws(()=>tools.start({kind:'netcat',host:'127.0.0.1',port:1,mode:'probe',transport:'udp'}),/UDP/);
 const job=tools.start({kind:'telnet',host:'private.invalid',port:23,vpnId:'vpn-fixture'});await until(()=>events.some(e=>e.id===job.id&&e.closed));assert.equal(calls.length,1);assert.equal(calls[0].routeMode,'vpn');assert.equal(calls[0].vpnId,'vpn-fixture');
});
test('Traceroute loopback streams real OS ICMP output and finishes',async t=>{
 const{tools,events}=setup(t);const job=tools.start({kind:'traceroute',host:'127.0.0.1',hops:2,wait:200});await until(()=>events.some(e=>e.id===job.id&&e.closed));assert.ok(events.some(e=>e.id===job.id&&e.data?.includes('127.0.0.1')));assert.ok(!events.some(e=>e.id===job.id&&e.error));
});
test('Native DNS tools query all record types over UDP/TCP and display sections, TTL, NXDOMAIN and reverse IP',async t=>{
 const fixture=await startDNS();t.after(()=>fixture.close());const{tools,events}=setup(t);
 for(const recordType of ['A','AAAA','CNAME','MX','NS','TXT','SOA','PTR','SRV','CAA','ANY']){
  const job=tools.start({kind:'dig',host:recordType==='PTR'?'203.0.113.10':'fixture.test',recordType,resolver:fixture.resolver,wait:1000,dnsTCP:recordType==='AAAA'});await until(()=>events.some(e=>e.id===job.id&&e.closed));const output=events.filter(e=>e.id===job.id).map(e=>e.data||'').join('');assert.ok(output.includes('status: NOERROR'),output);assert.ok(output.includes(recordType==='PTR'?'10.113.0.203.in-addr.arpa':'fixture.test'));assert.ok(output.includes('300\tIN\t'));assert.ok(output.includes('AUTHORITY SECTION'));assert.ok(!events.some(e=>e.id===job.id&&e.error));
 }
 const lookup=tools.start({kind:'nslookup',host:'fixture.test',resolver:fixture.resolver});await until(()=>events.some(e=>e.id===lookup.id&&e.closed));assert.ok(events.some(e=>e.id===lookup.id&&e.data?.includes('203.0.113.10')));
 const missing=tools.start({kind:'dig',host:'missing.test',resolver:fixture.resolver,recursion:false});await until(()=>events.some(e=>e.id===missing.id&&e.closed));assert.ok(events.some(e=>e.id===missing.id&&e.data?.includes('NXDOMAIN')));assert.equal(fixture.requests.at(-1).query.readUInt16BE(2)&256,0);
 assert.ok(plan({host:'2001:db8::1',recordType:'PTR',resolver:fixture.resolver}).name.endsWith('.ip6.arpa'));assert.equal(plan({host:'.',recordType:'NS'}).name,'.');assert.deepEqual(resolver('[::1]:5353'),{host:'::1',port:5353});
});
test('DNS truncation retries TCP; timeout, cancellation, malformed packets and unsafe names are bounded',async t=>{
 const fixture=await startDNS({truncate:true}),drop=await startDNS({drop:true});t.after(()=>Promise.all([fixture.close(),drop.close()]));const{tools,events}=setup(t);
 const job=tools.start({kind:'dig',host:'fixture.test',resolver:fixture.resolver});await until(()=>events.some(e=>e.id===job.id&&e.closed));assert.deepEqual(fixture.requests.map(r=>r.tcp),[false,true]);assert.ok(events.some(e=>e.id===job.id&&e.data?.includes('(TCP)')));
 const failed=tools.start({kind:'dig',host:'fixture.test',resolver:drop.resolver,wait:100});await until(()=>events.some(e=>e.id===failed.id&&e.error));assert.ok(events.some(e=>e.id===failed.id&&e.error?.includes('timed out')));
 const cancelled=tools.start({kind:'nslookup',host:'fixture.test',resolver:drop.resolver});await pause(30);tools.stop(cancelled.id);assert.ok(!tools.jobs.has(cancelled.id));
 assert.throws(()=>plan({host:'bad name.test'}),/Invalid DNS/);assert.throws(()=>resolver('dns.invalid'),/IP address/);assert.throws(()=>plan({host:'fixture.test',recordType:'INVALID'}),/Unsupported/);
 const loop=Buffer.from('000180000001000000000000c00c00010001','hex');assert.throws(()=>parse(loop,1),/compression loop/);assert.throws(()=>parse(Buffer.alloc(2),1),/Invalid/);
});
test('Ping loopback uses OS ICMP and reports replies and statistics',async t=>{
 const{tools,events}=setup(t),job=tools.start({kind:'ping',host:'127.0.0.1',count:1,wait:200});await until(()=>events.some(e=>e.id===job.id&&e.closed));assert.ok(events.some(e=>e.id===job.id&&e.data?.includes('127.0.0.1')));assert.ok(!events.some(e=>e.id===job.id&&e.error));
});
