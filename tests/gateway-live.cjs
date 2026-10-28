const fs = require('node:fs');
const path = require('node:path');
const { spawn } = require('node:child_process');
const assert = require('node:assert/strict');
const { argumentsFor, freePort } = require('../electron/gateways.cjs');
const { socksDial } = require('../electron/routes.cjs');
const root = path.resolve('vpn-runtime'), initrd = path.resolve('runtime-cache/gateway-test/images/gateway-initrd.gz');
const children = [], diagnostics = [];
function guest(name, port, link, role, message) {
  let resolve, reject, ready = false;
  const promise = new Promise((a,b) => { resolve=a; reject=b; });
  const binary = process.platform === 'win32' ? path.join(root,'qemu/qemu-system-x86_64.exe') : 'qemu-system-x86_64';
  const child=spawn(binary,argumentsFor(root,port,{initrd,serial:'file:'+path.resolve('runtime-cache/'+name+'.log'),extra:['-netdev',`socket,id=link,${role}=127.0.0.1:${link}`,'-device',`virtio-net-pci,netdev=link,mac=52:54:00:11:00:${role==='listen'?'01':'02'}`]}),{windowsHide:true,stdio:['pipe','pipe','pipe']});
  children.push(child); let buffer='';
  child.stderr.on('data',data=>{process.stderr.write(name+': '+data);});
  child.stdin.on('error',()=>{});
  child.on('error',reject); child.on('exit',code=>{if(!ready)reject(new Error(name+' exited '+code));});
  child.stdout.on('data',data=>{
    buffer+=data.toString();let end;
    while((end=buffer.indexOf('\n'))>=0){const line=buffer.slice(0,end);buffer=buffer.slice(end+1);let e;try{e=JSON.parse(line);}catch{continue;}
      if(e.event==='diagnostics'){diagnostics.push({name,...e});fs.writeFileSync('test-results/gateway-diagnostics.json',JSON.stringify(diagnostics,null,2));continue;}
      console.log(name,JSON.stringify(e));
      if(e.event==='booted'){child.stdin.write(JSON.stringify(message)+'\n');setTimeout(()=>{if(!ready)for(const c of children)c.stdin.write('{"command":"diagnose"}\n');},20000).unref();}
      if(e.event==='ready'||e.event==='server-ready'){ready=true;resolve(child);}
      if(e.event==='failed'){child.stdin.write('{"command":"diagnose"}\n');reject(new Error(name+': '+e.reason));}
    }
  });
  return { child, promise };
}
async function probe(ipsec,tag,keep=false) {
  const link=await freePort(), serverPort=await freePort(), clientPort=await freePort();
  const server=guest('vpn-peer-'+tag,serverPort,link,'listen',{command:'test-server',ipsec,tag});
  await server.promise;
  const profile={name:'Fixture '+tag,gateway:'198.18.0.1',username:'connector-test',protocol:ipsec?'l2tp-ipsec-psk':'l2tp',authMethod:'mschapv2',mtu:1400,dns:['10.77.0.1'],allowedCidrs:['10.77.0.0/24'],ike:'aes256-sha256-modp2048!',esp:'aes256-sha256!',remoteId:''};
  const proxy={port:clientPort,username:'test-client',password:'test-proxy-password'};
  const client=guest('vpn-client-'+tag,clientPort,link,'connect',{command:'start',profile,password:'connector-test-password',psk:'connector-test-psk',proxy,testLink:'198.18.0.2/24'});
  await client.promise;
  const stream=await socksDial(proxy,'fixture.internal.invalid',2222);
  const received=await new Promise((resolve,reject)=>{let text='';const timer=setTimeout(()=>reject(new Error('VPN TCP echo timed out')),10000);stream.on('error',reject);stream.on('data',b=>{text+=b.toString();if(text.includes('route-probe')){clearTimeout(timer);resolve(text);}});stream.resume();stream.write('route-probe');});
  assert.match(received,new RegExp(tag));
  await assert.rejects(()=>socksDial(proxy,'192.0.2.15',2222),/VPN could not reach/,'destination outside allowed prefixes is blocked');
  if(keep)return {profile,proxy,client,server,stream};
  let closed=false;stream.once('close',()=>{closed=true;});client.child.kill();
  for(let i=0;i<100&&!closed;i++)await new Promise(r=>setTimeout(r,100));
  assert.equal(closed,true,'VPN loss closes dependent TCP instead of routing directly');
  server.child.kill();return {protocol:profile.protocol,vpnOnlyDNS:true,tcpEcho:true,failClosed:true};
}
const deadline=setTimeout(()=>{for(const c of children){try{c.stdin.write('{"command":"diagnose"}\n');}catch{}}setTimeout(()=>{children.forEach(c=>c.kill());process.exit(1);},1500);},180000);
(async()=>{
 let result;
 if(process.env.CONNECTOR_TEST_OVERLAP==='1'){
  const a=await probe(true,'peer-A',true),b=await probe(false,'peer-B',true);
  let closed=false;a.stream.once('close',()=>{closed=true;});
  a.client.child.stdin.write('{"command":"test-drop-vpn"}\n');
  for(let i=0;i<100&&!closed;i++)await new Promise(r=>setTimeout(r,100));
  assert.equal(closed,true,'IPsec loss closes its existing TCP streams');
  const continued=await new Promise((resolve,reject)=>{let text='';const timer=setTimeout(()=>reject(new Error('Other VPN was disrupted')),10000);b.stream.on('data',data=>{text+=data.toString();if(text.includes('other-vpn-still-active')){clearTimeout(timer);resolve(true);}});b.stream.write('other-vpn-still-active');});
  assert.equal(continued,true);result={protocols:['l2tp-ipsec-psk','l2tp'],overlappingSubnet:'10.77.0.0/24',independentConcurrentVPNs:true,ipsecDropClosesOnlyDependentStreams:true,vpnOnlyDNS:true,allowedPrefixesEnforced:true};
 }else result=await probe(process.env.CONNECTOR_TEST_PLAIN!=='1','peer-A');
 fs.writeFileSync('test-results/gateway-live-report.json',JSON.stringify({passed:true,...result},null,2));console.log('Live gateway VPN/DNS/TCP test passed.');
})().catch(async error=>{console.error(error);for(const c of children){try{c.stdin.write('{"command":"diagnose"}\n');}catch{}}await new Promise(r=>setTimeout(r,1500));process.exitCode=1;}).finally(()=>{clearTimeout(deadline);children.forEach(c=>c.kill());});
