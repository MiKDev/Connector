const net=require('node:net'),dgram=require('node:dgram');
const name=s=>Buffer.concat([...s.split('.').flatMap(l=>[Buffer.from([l.length]),Buffer.from(l)]),Buffer.from([0])]);
function answer(query,{truncated=false}={}){
 let end=12;while(query[end])end+=query[end]+1;end++;const type=query.readUInt16BE(end),question=query.subarray(12,end+4),head=Buffer.alloc(12);head.writeUInt16BE(query.readUInt16BE(0));head.writeUInt16BE(truncated?0x8380:0x8180,2);head.writeUInt16BE(1,4);if(truncated)return Buffer.concat([head,question]);
 const record=(t,value,owner=Buffer.from([192,12]))=>{const h=Buffer.alloc(10);h.writeUInt16BE(t);h.writeUInt16BE(1,2);h.writeUInt32BE(300,4);h.writeUInt16BE(value.length,8);return Buffer.concat([owner,h,value]);};
 const numbers=Buffer.alloc(20);[1234,3600,600,86400,300].forEach((v,i)=>numbers.writeUInt32BE(v,i*4));
 const records={1:Buffer.from([203,0,113,10]),28:Buffer.from('20010db8000000000000000000000001','hex'),2:name('ns.fixture.test'),5:name('alias.fixture.test'),6:Buffer.concat([name('ns.fixture.test'),name('admin.fixture.test'),numbers]),12:name('ptr.fixture.test'),15:Buffer.concat([Buffer.from([0,10]),name('mail.fixture.test')]),16:Buffer.from([5,...Buffer.from('hello'),5,...Buffer.from('world')]),33:Buffer.concat([Buffer.from([0,1,0,5,1,187]),name('service.fixture.test')]),257:Buffer.concat([Buffer.from([0,5]),Buffer.from('issue'),Buffer.from('ca.fixture.test')])};
 const answers=type===255?Object.entries(records).map(([t,b])=>record(Number(t),b)):records[type]?[record(type,records[type])]:[];
 if(query.subarray(12,end).includes(Buffer.from('missing'))){head.writeUInt16BE(0x8183,2);head.writeUInt16BE(0,6);return Buffer.concat([head,question]);}
 head.writeUInt16BE(answers.length,6);head.writeUInt16BE(1,8);head.writeUInt16BE(1,10);return Buffer.concat([head,question,...answers,record(2,records[2]),record(1,records[1],name('ns.fixture.test'))]);
}
async function startDNS(options={}){
 const connections=new Set(),requests=[];const tcp=net.createServer(socket=>{connections.add(socket);socket.on('error',()=>{});socket.once('close',()=>connections.delete(socket));let data=Buffer.alloc(0);socket.on('data',b=>{data=Buffer.concat([data,b]);if(data.length>=2&&data.length>=data.readUInt16BE(0)+2){const query=data.subarray(2);requests.push({tcp:true,query});const response=answer(query),size=Buffer.alloc(2);size.writeUInt16BE(response.length);socket.end(Buffer.concat([size,response]));}});});
 await new Promise(r=>tcp.listen(0,'127.0.0.1',r));const port=tcp.address().port,udp=dgram.createSocket('udp4');udp.on('message',(query,r)=>{requests.push({tcp:false,query});if(!options.drop)udp.send(answer(query,{truncated:options.truncate}),r.port,r.address);});await new Promise(r=>udp.bind(port,'127.0.0.1',r));
 return {port,requests,resolver:'127.0.0.1:'+port,close:async()=>{for(const s of connections)s.destroy();await Promise.all([new Promise(r=>tcp.close(r)),new Promise(r=>udp.close(r))]);}};
}
module.exports={startDNS,answer};
