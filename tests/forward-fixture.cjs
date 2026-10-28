const net=require('node:net');
function attachForwarding(client,options={}){
 const listeners=new Set(),sockets=new Set();
 const track=s=>{sockets.add(s);s.on('error',()=>{});s.once('close',()=>sockets.delete(s));return s;};
 client.on('tcpip',(accept,reject,info)=>{
  if(options.denyLocal){reject();return;}
  const socket=track(net.createConnection({host:info.destIP,port:info.destPort,allowHalfOpen:true}));let stream,settled=false;
  socket.once('error',()=>{if(!settled){settled=true;reject();}stream?.destroy();});
  socket.once('connect',()=>{settled=true;stream=accept();stream.on('error',()=>socket.destroy());stream.on('close',()=>{if(stream.readableEnded)socket.end(()=>socket.destroy());else socket.destroy();});socket.pipe(stream).pipe(socket);});
  socket.once('close',()=>stream?.destroy());
 });
 client.on('request',(accept,reject,name,info)=>{
  if(name==='tcpip-forward'){
   if(options.denyRemote){reject();return;}
   let replied=false;
   const listener=net.createServer({pauseOnConnect:true,allowHalfOpen:true},socket=>{
    track(socket);client.forwardOut(info.bindAddr,listener.address().port,socket.remoteAddress,socket.remotePort,(error,stream)=>{if(error||socket.destroyed){socket.destroy();stream?.destroy();return;}
     // ssh2's server Channel closes both directions on writable finish. This
     // test-only TCP channel must preserve RFC-style EOF independently, as an
     // OpenSSH forwarded-tcpip channel does; it is not a server shell session.
     stream.server=false;
     stream.on('error',()=>socket.destroy());stream.on('close',()=>{if(stream.readableEnded)socket.end(()=>socket.destroy());else socket.destroy();});socket.on('close',()=>stream.destroy());socket.pipe(stream).pipe(socket);});
   });listeners.add(listener);
   listener.on('error',()=>{if(!replied){replied=true;reject();}listeners.delete(listener);});
   listener.listen(info.bindPort,info.bindAddr,()=>{if(!replied){replied=true;accept(listener.address().port);}});
  }else if(name==='cancel-tcpip-forward'){
   const listener=[...listeners].find(l=>l.address()?.port===info.bindPort);if(listener){listener.close();listeners.delete(listener);accept();}else reject();
  }else reject?.();
 });
 client.once('close',()=>{for(const s of sockets)s.destroy();for(const listener of listeners)listener.close();listeners.clear();});
}
module.exports={attachForwarding};
