const net=require('node:net');
const dgram=require('node:dgram');
const crypto=require('node:crypto');
const path=require('node:path');
const fs=require('node:fs');
const {spawn}=require('node:child_process');
const {StringDecoder}=require('node:string_decoder');
const {plan:planDNS,runDNS}=require('./dns-tools.cjs');
function host(value){if(typeof value!=='string'||!value||value.length>253||!/^[a-zA-Z0-9_.:\[\]%-]+$/.test(value)||value.startsWith('-'))throw new Error('Invalid destination host');return value.replace(/^\[|\]$/g,'');}
function integer(value,min,max,name){const n=Number(value);if(!Number.isInteger(n)||n<min||n>max)throw new Error('Invalid '+name);return n;}
// Incremental RFC 854 negotiation. Never render negotiation bytes as text.
class Telnet {
 constructor(send){this.send=send;this.state='data';this.command=0;this.sub=[];this.local=new Set();this.remote=new Set();}
 receive(buffer){const output=[];for(const b of buffer){switch(this.state){
 case 'data':if(b===255)this.state='iac';else output.push(b);break;
 case 'iac':if(b===255){output.push(b);this.state='data';}else if([251,252,253,254].includes(b)){this.command=b;this.state='option';}else if(b===250){this.sub=[];this.state='sub';}else this.state='data';break;
 case 'option':{const c=this.command,accept=c===251?[1,3].includes(b):[3,24,31].includes(b),set=c===251||c===252?this.remote:this.local;if(c===251||c===253){if(!set.has(b)){this.send(Buffer.from([255,c===251?(accept?253:254):(accept?251:252),b]));if(accept)set.add(b);if(c===253&&b===31)this.send(Buffer.from([255,250,31,0,100,0,30,255,240]));}}else set.delete(b);this.state='data';break;}
 case 'sub':if(b===255)this.state='sub-iac';else if(this.sub.length<512)this.sub.push(b);break;
 case 'sub-iac':if(b===240){if(this.sub[0]===24&&this.sub[1]===1)this.send(Buffer.from([255,250,24,0,...Buffer.from('xterm-256color'),255,240]));this.state='data';}else{if(b===255&&this.sub.length<512)this.sub.push(b);this.state='sub';}break;
 }}return Buffer.from(output);}
 encode(data){return Buffer.from(data.replace(/\r\n|\r|\n/g,'\r\n'),'utf8').reduce((a,b)=>{a.push(b);if(b===255)a.push(b);return a;},[]);}
}
class Diagnostics {
 constructor(routes,network,emit){this.routes=routes;this.network=network;this.emit=emit;this.jobs=new Map();this.closed=false;}
 publish(job,data={}){this.emit('diagnostic',{id:job.id,...data});}
 start(input={}){
  if(this.closed)throw new Error('Network tools closed');if(this.jobs.size>=12)throw new Error('Stop an existing tool first (maximum 12)');
  const kind=input.kind;if(!['telnet','netcat','traceroute','ping','nslookup','dig'].includes(kind))throw new Error('Invalid network tool');
  const dnsTool=['nslookup','dig'].includes(kind),icmp=['traceroute','ping'].includes(kind),query=dnsTool?planDNS(input):null;
  const mode=kind==='netcat'?(input.mode||'connect'):'connect';if(!['connect','listen','probe'].includes(mode))throw new Error('Invalid netcat mode');
  const udp=input.transport==='udp';if(udp&&kind!=='netcat')throw new Error('UDP is available in Netcat only');
  if(udp&&mode==='probe')throw new Error('UDP cannot reliably test open ports; use Connect');
  const target=host(input.host||'127.0.0.1'),port=icmp||dnsTool?0:integer(input.port,mode==='listen'?0:1,65535,'port');
  const hops=integer(input.hops||30,1,64,'hop limit'),wait=integer(input.wait||1000,100,5000,'probe wait');
  const count=integer(input.count||4,1,100,'ping count');
  const vpnId=input.vpnId||'';if(vpnId&&(udp||mode==='listen'||icmp||dnsTool))throw new Error('VPN routing supports outgoing TCP Telnet / Netcat only');
  if(vpnId){const vpn=this.network.get(vpnId);if(vpn.shared)throw new Error('Use a local VPN profile for network diagnostics');}
  if(mode==='listen'&&!net.isIP(target))throw new Error('Listener bind address must be an IP address');
  const job={id:crypto.randomUUID(),kind,mode,udp,target,port,controller:new AbortController(),resources:new Set(),decoder:new StringDecoder('utf8'),pending:0,bytes:0};
  this.jobs.set(job.id,job);
  // Defer so the renderer can install its session before output arrives.
  setImmediate(()=>this.run(job,{vpnId,hops,wait,count,query}).catch(e=>this.finish(job,e.message)));
  return {id:job.id,kind,mode,udp,host:target,port,route:vpnId?'VPN: '+this.network.get(vpnId).name:'Direct'};
 }
 track(job,resource){job.resources.add(resource);resource.on('error',e=>this.finish(job,e.message));return resource;}
 output(job,data){if(!this.jobs.has(job.id))return;job.bytes+=data.length;if(job.bytes>8*1024*1024){this.finish(job,'8 MiB output limit reached');return;}const visible=job.kind==='telnet'?job.telnet.receive(data):data;this.publish(job,{data:job.decoder.write(visible),hex:visible.toString('hex')});}
 async run(job,{vpnId,hops,wait,count,query}){
  if(!this.jobs.has(job.id))return;
  if(query)return runDNS(job,query,this,wait);
  if(['traceroute','ping'].includes(job.kind)){
   const ping=job.kind==='ping',command=process.platform==='win32'?path.join(process.env.SystemRoot||'C:\\Windows','System32',ping?'ping.exe':'tracert.exe'):'python3';
   const args=process.platform==='win32'?(ping?['-n',String(count),'-w',String(wait),'-l','32',job.target]:['-d','-h',String(hops),'-w',String(wait),job.target]):['-I','-c',fs.readFileSync(path.join(__dirname,ping?'ping-probe.py':'trace-route.py'),'utf8'),job.target,String(ping?count:hops),String(wait)];
   const child=spawn(command,args,{windowsHide:true,stdio:['ignore','pipe','pipe']});job.child=child;child.on('error',e=>this.finish(job,'Cannot start OS trace probe: '+e.message));
   child.stdout.on('data',d=>this.output(job,d));child.stderr.on('data',d=>this.output(job,d));child.once('close',code=>this.finish(job,code?'Trace probe exited with code '+code:''));
   job.timer=setTimeout(()=>this.finish(job,'ICMP probe time limit reached'),Math.min(300000,ping?count*Math.max(1000,wait)+15000:hops*wait*3+15000));return;
  }
  if(job.kind==='telnet')job.telnet=new Telnet(buffer=>job.socket?.write(buffer));
  if(job.udp){
   const socket=this.track(job,dgram.createSocket(net.isIP(job.target)===6?'udp6':'udp4'));job.socket=socket;
   socket.on('message',(data,remote)=>{job.remote=remote;this.output(job,data);});
   if(job.mode==='listen')socket.bind(job.port,job.target,()=>this.publish(job,{status:'listening',port:socket.address().port}));
   else socket.connect(job.port,job.target,()=>this.publish(job,{status:'connected',note:'UDP has no handshake; no response does not prove a port is open.'}));return;
  }
  const attach=socket=>{job.socket=socket;this.track(job,socket);socket.setNoDelay(true);socket.on('data',d=>this.output(job,d));socket.once('end',()=>{socket.end();});socket.once('close',()=>this.finish(job));this.publish(job,{status:'connected',peer:`${socket.remoteAddress}:${socket.remotePort}`});};
  if(job.mode==='listen'){
   const listener=this.track(job,net.createServer(socket=>{if(job.socket){socket.destroy();return;}attach(socket);listener.close();}));
   listener.listen(job.port,job.target,()=>this.publish(job,{status:'listening',port:listener.address().port}));return;
  }
  job.timer=setTimeout(()=>this.finish(job,'Connection timed out'),25000);
  const result=await this.routes.dial({id:'diagnostic:'+job.id,host:job.target,port:job.port,routeMode:vpnId?'vpn':'direct',vpnId},job.controller.signal);
  clearTimeout(job.timer);if(!this.jobs.has(job.id)){result.socket.destroy();return;}
  if(job.mode==='probe'){result.socket.destroy();this.publish(job,{data:`TCP ${job.target}:${job.port} is open\r\n`});this.finish(job);return;}
  attach(result.socket);result.socket.resume();
 }
 write(id,data,encoding='text'){
  const job=this.jobs.get(id);if(!job?.socket||job.mode==='probe')throw new Error('Tool is not connected');
  if(typeof data!=='string'||data.length>65536||!['text','hex'].includes(encoding)||encoding==='hex'&&(!/^(?:[a-fA-F0-9]{2}\s*)+$/.test(data)))throw new Error('Invalid payload (maximum 64 KiB)');
  let buffer=encoding==='hex'?Buffer.from(data.replace(/\s/g,''),'hex'):Buffer.from(data);if(job.kind==='telnet')buffer=Buffer.from(job.telnet.encode(data));
  if(job.udp){if(buffer.length>65507)throw new Error('UDP payload too large');if(job.mode==='listen'){if(!job.remote)throw new Error('Wait for a datagram before replying');job.socket.send(buffer,job.remote.port,job.remote.address);}else job.socket.send(buffer);}
  else{if(job.socket.destroyed||!job.socket.writable)throw new Error('Connection closed');if(job.socket.writableLength>262144)throw new Error('Socket is busy; wait before sending more');job.socket.write(buffer);}
 }
 finish(job,error=''){if(!this.jobs.delete(job.id))return;clearTimeout(job.timer);job.controller.abort();job.child?.kill();for(const r of job.resources){try{if(r.destroy)r.destroy();else r.close();}catch{}}this.publish(job,{closed:true,status:error?'failed':'closed',error,data:job.decoder.end()});}
 stop(id){const job=this.jobs.get(id);if(job)this.finish(job);}
 shutdown(){this.closed=true;for(const job of [...this.jobs.values()])this.finish(job);}
}
module.exports={Diagnostics,Telnet};
