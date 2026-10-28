const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const net = require('node:net');
const { spawn } = require('node:child_process');
const { snapshot } = require('./core.cjs');
const { publicVPN } = require('./network-config.cjs');
function freePort() { return new Promise((resolve, reject) => { const server = net.createServer(); server.once('error', reject); server.listen(0, '127.0.0.1', () => { const port = server.address().port; server.close(() => resolve(port)); }); }); }
function abortable(promise, signal) {
  if (!signal) return promise;
  if (signal.aborted) return Promise.reject(new Error('Connection cancelled'));
  return new Promise((resolve, reject) => { const abort = () => reject(new Error('Connection cancelled')); signal.addEventListener('abort', abort, { once: true }); promise.then(resolve, reject).finally(() => signal.removeEventListener('abort', abort)); });
}
function argumentsFor(root, port, options = {}) {
  return ['-machine','q35,accel=tcg','-cpu','max','-m','512','-smp','2','-nodefaults','-no-user-config','-display','none','-monitor','none',
    '-serial', options.serial || 'none','-no-reboot','-kernel',path.join(root,'images/vmlinuz'),'-initrd',options.initrd || path.join(root,'images/gateway-initrd.gz'),
    '-append','console=ttyS0 panic=-1 net.ifnames=0','-netdev',`user,id=net0,hostfwd=tcp:127.0.0.1:${port}-:1080`,'-device','virtio-net-pci,netdev=net0',
    '-device','virtio-serial-pci','-chardev','stdio,id=control,signal=off','-device','virtserialport,chardev=control,name=org.connector.vpn', ...(options.extra || [])];
}
class Gateways {
  constructor(config, vault, root, emit) { this.config = config; this.vault = vault; this.root = root; this.emit = emit; this.instances = new Map(); this.verified = false; }
  binary() { return process.platform === 'win32' ? path.join(this.root, 'qemu/qemu-system-x86_64.exe') : 'qemu-system-x86_64'; }
  async verify() {
    if (this.verified) return;
    const manifestPath = path.join(this.root, 'manifest.json');
    if (!fs.existsSync(manifestPath)) throw new Error('VPN gateway runtime is missing. Install the complete Connector VPN package.');
    const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
    for (const name of ['vmlinuz', 'gateway-initrd.gz']) {
      const hash = crypto.createHash('sha256'); for await (const chunk of fs.createReadStream(path.join(this.root, 'images', name))) hash.update(chunk);
      if (hash.digest('hex') !== manifest.images?.[name]) throw new Error('VPN gateway image integrity check failed');
    }
    this.verified = true;
  }
  state() { return this.config.vpns().map(vpn => { const i = this.instances.get(vpn.id); return { vpnId: vpn.id, state: i?.state || 'stopped', reason: i?.reason || '', connections: i?.sockets.size || 0, dns: i?.dns || [] }; }); }
  changed() { this.emit('network', { gateways: this.state() }); }
  closeSockets(instance) { for (const socket of instance.sockets) socket.destroy(); instance.sockets.clear(); }
  track(id, socket) { const instance = this.instances.get(id); if (!instance || instance.state !== 'ready') { socket.destroy(); throw new Error('VPN is no longer ready'); } instance.sockets.add(socket); socket.once('close', () => { instance.sockets.delete(socket); this.changed(); }); this.changed(); }
  async ensure(id, signal) {
    const vpn = this.config.get(id); let instance = this.instances.get(id);
    this.authorize?.(vpn);
    if (instance && instance.fingerprint !== snapshot(vpn)) { this.stop(id); instance = null; }
    if (instance && ['failed','stopped','down'].includes(instance.state)) { this.stop(id); instance = null; }
    if (!instance) {
      if ([...this.instances.values()].filter(i => !['failed','stopped'].includes(i.state)).length >= 4) throw new Error('Maximum four simultaneous VPN gateways (512 MiB each). Stop an unused VPN first.');
      instance = { id, fingerprint: snapshot(vpn), state: 'starting', reason: '', sockets: new Set(), proxy: { username: 'connector', password: crypto.randomBytes(32).toString('hex') }, process: null };
      this.instances.set(id, instance);
      instance.promise = this.start(instance, vpn).catch(error => { if (instance.state !== 'stopped') { instance.state = 'failed'; instance.reason = error.message; } this.closeSockets(instance); instance.process?.kill(); this.changed(); throw error; });
      // Retain the failure for pending callers without an unhandled rejection.
      instance.promise.catch(() => {}); this.changed();
    }
    return abortable(instance.promise, signal);
  }
  async start(instance, vpn) {
    await this.verify();
    if (!vpn.passwordSecret || (vpn.protocol !== 'l2tp' && !vpn.pskSecret)) throw new Error('Configure this VPN’s credentials before starting it');
    if (!this.vault.available()) throw new Error('Unlock the OS credential vault to connect this VPN');
    instance.proxy.port = await freePort();
    if (instance.state === 'stopped') throw new Error('VPN start cancelled');
    const child = spawn(this.binary(), argumentsFor(this.root, instance.proxy.port), { windowsHide: true, stdio: ['pipe','pipe','pipe'] }); instance.process = child;
    return new Promise((resolve, reject) => {
      let buffer = '', settled = false, stderr = '';
      const timer = setTimeout(() => { reject(new Error('VPN gateway did not become ready within 120 seconds')); child.kill(); }, 120000);
      const fail = error => { clearTimeout(timer); this.closeSockets(instance); if (!settled) { settled = true; reject(error); } else { instance.state = 'failed'; instance.reason = error.message; this.changed(); } };
      child.stdin.on('error', error => { if (instance.state !== 'stopped') fail(new Error('VPN control channel closed')); child.kill(); });
      child.once('error', error => fail(new Error('Cannot launch the isolated VPN runtime: ' + error.message)));
      child.once('exit', () => { if (instance.state !== 'stopped') fail(new Error(stderr.includes('host forwarding') ? 'VPN local port could not be reserved. Retry the VPN.' : 'VPN gateway exited; dependent connections closed')); else { clearTimeout(timer); if (!settled) { settled = true; reject(new Error('VPN stopped')); } } });
      child.stderr.on('data', data => { stderr = (stderr + data.toString()).slice(-4096); });
      child.stdout.on('data', data => {
        buffer += data.toString('utf8'); if (buffer.length > 65536) { fail(new Error('Invalid VPN control response')); child.kill(); return; }
        let end;
        while ((end = buffer.indexOf('\n')) >= 0) {
          const line = buffer.slice(0, end); buffer = buffer.slice(end + 1);
          let message; try { message = JSON.parse(line); } catch { fail(new Error('Invalid VPN control response')); child.kill(); return; }
          if (instance.state === 'stopped') continue;
          if (message.event === 'booted') {
            if (instance.state === 'stopped') { child.kill(); return; }
            instance.state = 'connecting'; this.changed();
            try { child.stdin.write(JSON.stringify({ command: 'start', profile: publicVPN(vpn), password: this.vault.decrypt(vpn.passwordSecret), psk: vpn.pskSecret ? this.vault.decrypt(vpn.pskSecret) : '', proxy: instance.proxy }) + '\n'); }
            catch { fail(new Error('VPN credentials could not be opened from the OS vault')); child.kill(); }
          } else if (message.event === 'phase') { instance.state = String(message.phase); this.changed(); }
          else if (message.event === 'ready') { clearTimeout(timer); instance.state = 'ready'; instance.dns = message.dns || []; instance.reason = ''; this.changed(); if (!settled) { settled = true; resolve(instance.proxy); } }
          else if (message.event === 'down') { instance.state = 'down'; instance.reason = 'VPN link lost; dependent connections closed'; this.closeSockets(instance); this.changed(); }
          else if (message.event === 'failed') { fail(new Error(String(message.reason || 'VPN negotiation failed').slice(0, 500))); child.kill(); }
        }
      });
    });
  }
  stop(id) { const instance = this.instances.get(id); if (!instance) return; instance.state = 'stopped'; instance.reason = ''; this.closeSockets(instance); if (instance.process) { try { instance.process.stdin.write('{"command":"stop"}\n'); } catch {} instance.process.kill(); } this.changed(); }
  shutdown() { for (const id of this.instances.keys()) this.stop(id); }
}
module.exports = { Gateways, argumentsFor, freePort, abortable };
