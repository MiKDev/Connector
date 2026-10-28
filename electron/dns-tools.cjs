const dns=require('node:dns'),net=require('node:net'),dgram=require('node:dgram'),crypto=require('node:crypto');
const {domainToASCII}=require('node:url');const ipaddr=require('ipaddr.js');
const types={A:1,NS:2,CNAME:5,SOA:6,PTR:12,MX:15,TXT:16,AAAA:28,SRV:33,CAA:257,ANY:255};
const typeName=n=>Object.keys(types).find(k=>types[k]===n)||'TYPE'+n;
function question(host,type){
 if(host==='.')return {name:'.',bytes:Buffer.from([0])};
 if(type==='PTR'&&net.isIP(host)){const a=ipaddr.parse(host);host=a.kind()==='ipv4'?a.toByteArray().reverse().join('.')+'.in-addr.arpa':a.toByteArray().map(v=>v.toString(16).padStart(2,'0')).join('').split('').reverse().join('.')+'.ip6.arpa';}
 const ascii=domainToASCII(host.replace(/\.$/,''));if(!ascii||ascii.length>253)throw new Error('Invalid DNS query name');const labels=ascii.split('.');if(labels.some(l=>!l||Buffer.byteLength(l)>63||!/^[a-zA-Z0-9_-]+$/.test(l)))throw new Error('Invalid DNS label');return {name:ascii,bytes:Buffer.concat([...labels.flatMap(l=>[Buffer.from([Buffer.byteLength(l)]),Buffer.from(l)]),Buffer.from([0])])};
}
function parse(packet,id){
 if(packet.length<12||packet.readUInt16BE(0)!==id||!(packet.readUInt16BE(2)&0x8000))throw new Error('Invalid DNS response');
 const need=(offset,size)=>{if(offset<0||offset+size>packet.length)throw new Error('Truncated DNS response');};
 const name=offset=>{let current=offset,end=null,labels=[],seen=new Set();for(let i=0;i<128;i++){need(current,1);if(seen.has(current))throw new Error('DNS compression loop');seen.add(current);const length=packet[current++];if(!length)return {value:labels.join('.')||'.',end:end??current};if((length&192)===192){need(current,1);end??=current+1;current=((length&63)<<8)|packet[current];continue;}if(length>63)throw new Error('Invalid DNS label');need(current,length);labels.push(packet.subarray(current,current+length).toString('ascii'));current+=length;}throw new Error('DNS compression depth exceeded');};
 const flags=packet.readUInt16BE(2),counts=[4,6,8,10].map(i=>packet.readUInt16BE(i));if(counts.reduce((a,b)=>a+b,0)>4096)throw new Error('Too many DNS records');
 let offset=12;const questions=[];for(let i=0;i<counts[0];i++){const n=name(offset);offset=n.end;need(offset,4);questions.push({name:n.value,type:typeName(packet.readUInt16BE(offset)),class:packet.readUInt16BE(offset+2)});offset+=4;}
 const sections=[];for(const count of counts.slice(1)){const records=[];for(let i=0;i<count;i++){
  const n=name(offset);offset=n.end;need(offset,10);const type=packet.readUInt16BE(offset),klass=packet.readUInt16BE(offset+2),ttl=packet.readUInt32BE(offset+4),length=packet.readUInt16BE(offset+8);offset+=10;need(offset,length);const start=offset,end=offset+length;let value;
  const rname=at=>{const result=name(at);if(result.end>end)throw new Error('Invalid DNS record name');return result;};
  if(type===1&&length===4)value=[...packet.subarray(start,end)].join('.');
  else if(type===28&&length===16)value=ipaddr.fromByteArray([...packet.subarray(start,end)]).toString();
  else if([2,5,12].includes(type))value=rname(start).value;
  else if(type===15&&length>=3)value=packet.readUInt16BE(start)+' '+rname(start+2).value;
  else if(type===33&&length>=7)value=[packet.readUInt16BE(start),packet.readUInt16BE(start+2),packet.readUInt16BE(start+4),rname(start+6).value].join(' ');
  else if(type===16){const chunks=[];let at=start;while(at<end){const l=packet[at++];if(at+l>end)throw new Error('Invalid DNS TXT record');chunks.push(JSON.stringify(packet.subarray(at,at+l).toString('utf8')));at+=l;}value=chunks.join(' ');}
  else if(type===6){const primary=rname(start),mail=rname(primary.end);if(mail.end+20>end)throw new Error('Invalid DNS SOA');value=[primary.value,mail.value,...[0,4,8,12,16].map(v=>packet.readUInt32BE(mail.end+v))].join(' ');}
  else if(type===257&&length>=2){const l=packet[start+1];if(start+2+l>end)throw new Error('Invalid DNS CAA');value=packet[start]+' '+packet.subarray(start+2,start+2+l).toString('ascii')+' '+JSON.stringify(packet.subarray(start+2+l,end).toString('utf8'));}
  else value='\\# '+length+' '+packet.subarray(start,end).toString('hex');
  records.push({name:n.value,type:typeName(type),class:klass,ttl,value});offset=end;
 }sections.push(records);}
 return {flags,rcode:flags&15,truncated:!!(flags&512),questions,answers:sections[0],authority:sections[1],additional:sections[2]};
}
function resolver(value){const raw=value||dns.getServers()[0];if(!raw)throw new Error('No system DNS resolver configured');let host=raw,port=53;const v6=/^\[([^\]]+)\](?::(\d+))?$/.exec(raw);if(v6){host=v6[1];port=Number(v6[2]||53);}else if(!net.isIP(raw)){const v4=/^([\d.]+):(\d+)$/.exec(raw);if(v4){host=v4[1];port=Number(v4[2]);}}if(!net.isIP(host)||!Number.isInteger(port)||port<1||port>65535)throw new Error('DNS resolver must be an IP address, optionally with a port');return {host,port};}
function plan(input){const type=input.recordType||'A';if(!types[type])throw new Error('Unsupported DNS record type');const q=question(input.host,type),id=crypto.randomInt(65536),head=Buffer.alloc(12);head.writeUInt16BE(id);head.writeUInt16BE(input.recursion===false?0:256,2);head.writeUInt16BE(1,4);const tail=Buffer.alloc(4);tail.writeUInt16BE(types[type]);tail.writeUInt16BE(1,2);return {id,name:q.name,type,server:resolver(input.resolver),tcp:input.dnsTCP===true,packet:Buffer.concat([head,q.bytes,tail])};}
function exchange(query,tcp,job,tools,wait){return new Promise((resolve,reject)=>{
 let settled=false,timer,socket;const done=(error,packet)=>{if(settled)return;settled=true;clearTimeout(timer);job.controller.signal.removeEventListener('abort',abort);if(socket){job.resources.delete(socket);socket.removeAllListeners('error');socket.on('error',()=>{});try{if(tcp)socket.destroy();else socket.close();}catch{}}if(error)reject(error);else resolve(packet);};
 const abort=()=>done(new Error('DNS query cancelled'));if(job.controller.signal.aborted){reject(new Error('DNS query cancelled'));return;}job.controller.signal.addEventListener('abort',abort,{once:true});
 timer=setTimeout(()=>done(new Error('DNS query timed out')),wait);
 try{if(tcp){socket=net.connect(query.server.port,query.server.host);let data=Buffer.alloc(0);socket.on('connect',()=>{const size=Buffer.alloc(2);size.writeUInt16BE(query.packet.length);socket.write(Buffer.concat([size,query.packet]));});socket.on('data',chunk=>{data=Buffer.concat([data,chunk]);if(data.length>65537){done(new Error('DNS TCP response too large'));return;}if(data.length>=2&&data.length>=data.readUInt16BE(0)+2)done(null,data.subarray(2,2+data.readUInt16BE(0)));});socket.on('close',()=>{if(!settled)done(new Error('DNS TCP connection closed'));});}
 else{socket=dgram.createSocket(net.isIP(query.server.host)===6?'udp6':'udp4');socket.on('message',packet=>{if(packet.length>=2&&packet.readUInt16BE(0)===query.id)done(null,packet);});socket.connect(query.server.port,query.server.host,()=>socket.send(query.packet));}
 job.resources.add(socket);socket.once('error',error=>done(error));
 }catch(e){done(e);}
 });}
async function runDNS(job,query,tools,wait){const start=Date.now();let tcp=query.tcp,packet=await exchange(query,tcp,job,tools,wait);if(packet.length>=12&&packet.readUInt16BE(0)===query.id&&(packet.readUInt16BE(2)&512)&&!tcp){tcp=true;packet=await exchange(query,true,job,tools,wait);}const result=parse(packet,query.id),statuses=['NOERROR','FORMERR','SERVFAIL','NXDOMAIN','NOTIMP','REFUSED'];
 const line=r=>`${r.name}\t${r.ttl}\t${r.class===1?'IN':r.class}\t${r.type}\t${r.value}`;let lines;
 if(job.kind==='nslookup')lines=[`Server: ${query.server.host}:${query.server.port}`,`Name: ${query.name}`,`Status: ${statuses[result.rcode]||result.rcode}`,result.flags&1024?'Authoritative answer:':'Non-authoritative answer:',...result.answers.map(line),...result.authority.map(r=>'Authority: '+line(r))];
 else{const flags=[[32768,'qr'],[1024,'aa'],[512,'tc'],[256,'rd'],[128,'ra'],[32,'ad'],[16,'cd']].filter(([bit])=>result.flags&bit).map(([,label])=>label).join(' ');lines=[`; Connector Dig ${query.name} ${query.type}`,`;; HEADER status: ${statuses[result.rcode]||result.rcode}, id: ${query.id}`,`;; flags: ${flags}; QUERY: ${result.questions.length}, ANSWER: ${result.answers.length}, AUTHORITY: ${result.authority.length}, ADDITIONAL: ${result.additional.length}`,';; QUESTION SECTION:',...result.questions.map(q=>`;${q.name}\tIN\t${q.type}`),'',...['answers','authority','additional'].flatMap(section=>[`;; ${section.toUpperCase()} SECTION:`,...result[section].map(line),''])];}
 lines.push(`;; Query time: ${Date.now()-start} ms`,`;; SERVER: ${query.server.host}:${query.server.port} (${tcp?'TCP':'UDP'})`,`;; Received: ${packet.length} bytes`);tools.output(job,Buffer.from(lines.join('\r\n')+'\r\n'));tools.finish(job);
}
module.exports={plan,parse,runDNS,types,resolver};
