const net = require('node:net');
const crypto = require('node:crypto');
const { text, snapshot } = require('./core.cjs');
function normalizeForward(input, id = crypto.randomUUID()) {
  if (!input || !['local','remote'].includes(input.kind)) throw new Error('Choose Local or Remote forwarding');
  const listenHost = input.listenHost || '127.0.0.1';
  if (!net.isIP(listenHost)) throw new Error('Bind address must be an IPv4 or IPv6 address');
  const listenPort = Number(input.listenPort), targetPort = Number(input.targetPort);
  if (!Number.isInteger(listenPort) || listenPort < 0 || listenPort > 65535) throw new Error('Listen port must be 0–65535 (0 allocates a free port)');
  if (!Number.isInteger(targetPort) || targetPort < 1 || targetPort > 65535) throw new Error('Destination port must be 1–65535');
  const targetHost = text(input.targetHost, 'destination host', 253);
  if (!net.isIP(targetHost) && !/^[a-zA-Z0-9](?:[a-zA-Z0-9.-]*[a-zA-Z0-9])?$/.test(targetHost)) throw new Error('Enter a destination hostname or IP without a URL or port');
  return { id, name:text(input.name,'tunnel name',80), serverId:text(input.serverId,'SSH connection',80), kind:input.kind, listenHost, listenPort, targetHost, targetPort };
}
class Forwards {
  constructor(store, ssh, emit = () => {}) {
    this.store=store;this.ssh=ssh;this.emit=emit;this.active=new Map();this.closed=false;
    store.db.run('CREATE TABLE IF NOT EXISTS ssh_forwards (id TEXT PRIMARY KEY,data TEXT NOT NULL)');
    this.timer=setInterval(()=>{for(const e of this.active.values())if(['starting','running'].includes(e.status)){try{this.check(e);}catch(error){this.finish(e,'failed',error.message);}}},1000);this.timer.unref();
  }
  all(){return this.store.rows('SELECT data FROM ssh_forwards ORDER BY id').map(r=>JSON.parse(r.data));}
  get(id){const row=this.store.rows('SELECT data FROM ssh_forwards WHERE id=?',[id])[0];if(!row)throw new Error('Port forward no longer exists');return JSON.parse(row.data);}
  state(){return this.all().map(p=>{const e=this.active.get(p.id);return {...p,status:e?.status||'stopped',boundPort:e?.boundPort||null,connections:e?.pairs.size||0,totalConnections:e?.total||0,lastError:e?.lastError||''};});}
  changed(){if(!this.closed)this.emit('forwards',{forwards:this.state()});}
  save(input,id){if(id)this.get(id);if(!id&&this.all().length>=128)throw new Error('Maximum 128 saved forwards');const p=normalizeForward(input,id);this.store.get(p.serverId);this.stop(p.id);this.active.delete(p.id);this.store.db.run('INSERT OR REPLACE INTO ssh_forwards VALUES (?,?)',[p.id,JSON.stringify(p)]);this.store.audit('forward.saved',p.name);this.changed();return p;}
  remove(id){const p=this.get(id);this.stop(id);this.active.delete(id);this.store.db.run('DELETE FROM ssh_forwards WHERE id=?',[id]);this.store.audit('forward.removed',p.name);this.changed();}
  check(e){
    if(this.closed||e.controller.signal.aborted||!['starting','running'].includes(e.status))throw new Error('Port forward stopped');
    const server=this.store.get(e.profile.serverId);this.ssh.authorize?.(server,'forward');
    if(this.ssh.securitySnapshot(server)!==e.serverSnapshot||snapshot(this.get(e.id))!==e.profileSnapshot)throw new Error('SSH profile, route or forwarding configuration changed');
  }
  async operation(e,fn){
    if(e.controller.signal.aborted)throw new Error('Port forward stopped');
    return new Promise((resolve,reject)=>{
      let done=false;const finish=(error,result)=>{if(done)return;done=true;clearTimeout(timer);e.controller.signal.removeEventListener('abort',abort);error?reject(error):resolve(result);};
      const abort=()=>finish(new Error(e.lastError||'Port forward stopped')),timer=setTimeout(()=>finish(new Error('Port forwarding request timed out')),15000);timer.unref();e.controller.signal.addEventListener('abort',abort,{once:true});
      try{fn(finish);}catch(error){finish(error);}
    });
  }
  async start(id){
    if(this.closed)throw new Error('Port forwarding is shutting down');
    const previous=this.active.get(id);if(previous&&['starting','running'].includes(previous.status))throw new Error('This port forward is already active');
    if([...this.active.values()].filter(e=>['starting','running'].includes(e.status)).length>=16)throw new Error('Maximum 16 active port forwards');
    const profile=this.get(id),server=this.store.get(profile.serverId);this.ssh.authorize?.(server,'forward');
    const e={id,profile,profileSnapshot:snapshot(profile),serverSnapshot:this.ssh.securitySnapshot(server),status:'starting',controller:new AbortController(),pairs:new Set(),total:0,lastError:'',boundPort:null,client:null,listener:null};
    this.active.set(id,e);this.changed();
    try{
      e.client=await this.ssh.connect(server,c=>{e.client=c;},{capability:'forward',signal:e.controller.signal});
      e.client.on('error',error=>this.finish(e,'failed',error.message));e.client.once('close',()=>{if(['starting','running'].includes(e.status))this.finish(e,'failed','SSH connection closed');});
      this.check(e);
      if(profile.kind==='local'){
        e.listener=net.createServer({pauseOnConnect:true,allowHalfOpen:true},socket=>this.local(e,socket));
        e.listener.on('error',error=>this.finish(e,'failed',error.message));
        await this.operation(e,cb=>{e.listener.once('error',cb);e.listener.listen(profile.listenPort,profile.listenHost,()=>cb(null,e.listener.address()));});
        e.boundPort=e.listener.address().port;
      }else{
        e.client.on('tcp connection',(info,accept,reject)=>this.remote(e,info,accept,reject));
        e.boundPort=await this.operation(e,cb=>e.client.forwardIn(profile.listenHost,profile.listenPort,(error,port)=>cb(error,port||profile.listenPort)));
        if(!Number.isInteger(e.boundPort)||e.boundPort<1||e.boundPort>65535)throw new Error('SSH server returned an invalid listening port');
      }
      this.check(e);e.status='running';this.store.audit('forward.started',profile.name);this.changed();return this.state().find(p=>p.id===id);
    }catch(error){this.finish(e,'failed',error.message);throw error;}
  }
  pair(e,socket){
    this.check(e);if(e.pairs.size>=64)throw new Error('Maximum 64 TCP streams per port forward');
    const pair={socket,stream:null,closed:false};e.pairs.add(pair);this.changed();
    const close=()=>{if(pair.closed)return;pair.closed=true;e.pairs.delete(pair);pair.socket?.destroy();pair.stream?.destroy();this.changed();};
    pair.close=close;socket.on('error',error=>{if(!pair.closed)this.streamError(e,error);close();});socket.once('close',close);return pair;
  }
  pipe(e,pair,stream){
    if(pair.closed||e.status!=='running'){stream.destroy();pair.close();return;}
    try{this.check(e);}catch(error){stream.destroy();pair.close();this.finish(e,'failed',error.message);return;}
    pair.stream=stream;stream.on('error',error=>{this.streamError(e,error);pair.close();});stream.once('close',()=>{if(!pair.closed&&stream.readableEnded)pair.socket.end(pair.close);else pair.close();});e.total++;pair.socket.pipe(stream).pipe(pair.socket);this.changed();
  }
  streamError(e,error){if(['starting','running'].includes(e.status)){e.lastError=String(error.message||error).slice(0,300);this.changed();}}
  local(e,socket){
    let pair;try{if(e.status!=='running')throw new Error('Port forward is not running');pair=this.pair(e,socket);}catch{socket.destroy();return;}
    const timer=setTimeout(()=>{this.streamError(e,new Error('Forwarded destination connection timed out'));pair.close();},15000);timer.unref();socket.once('close',()=>clearTimeout(timer));
    try{e.client.forwardOut(socket.remoteAddress||'127.0.0.1',socket.remotePort||0,e.profile.targetHost,e.profile.targetPort,(error,stream)=>{clearTimeout(timer);if(error){this.streamError(e,error);pair.close();return;}this.pipe(e,pair,stream);});}catch(error){clearTimeout(timer);this.streamError(e,error);pair.close();}
  }
  remote(e,info,accept,reject){
    const wildcard=['0.0.0.0','::'].includes(e.profile.listenHost);
    if(e.status!=='running'||info.destPort!==e.boundPort||(!wildcard&&info.destIP!==e.profile.listenHost)){reject();return;}
    let socket,pair;try{this.check(e);if(e.pairs.size>=64)throw new Error('Maximum TCP streams reached');socket=net.createConnection({host:e.profile.targetHost,port:e.profile.targetPort,allowHalfOpen:true});pair=this.pair(e,socket);}catch{socket?.destroy();reject();return;}
    let accepted=false;const timer=setTimeout(()=>{if(!accepted){accepted=true;reject();this.streamError(e,new Error('Local destination connection timed out'));pair.close();}},15000);timer.unref();
    socket.once('close',()=>{clearTimeout(timer);if(!accepted){accepted=true;reject();}});
    socket.once('connect',()=>{clearTimeout(timer);try{this.check(e);if(pair.closed)throw new Error('Port forward stopped');accepted=true;this.pipe(e,pair,accept());}catch{if(!accepted){accepted=true;reject();}pair.close();}});
  }
  finish(e,status,error=''){
    if(!['starting','running'].includes(e.status))return;
    e.status=status;e.lastError=String(error||'').slice(0,300);e.controller.abort();
    e.listener?.close();for(const pair of [...e.pairs])pair.close();
    // Closing the dedicated SSH session cancels its remote listeners and streams.
    e.client?.destroy();this.changed();
  }
  stop(id){const e=this.active.get(id);if(e)this.finish(e,'stopped');}
  invalidateServer(id){for(const e of this.active.values())if(e.profile.serverId===id)this.finish(e,'failed','SSH profile or sharing access changed');}
  shutdown(){this.closed=true;clearInterval(this.timer);for(const id of this.active.keys())this.stop(id);}
}
module.exports={Forwards,normalizeForward};
