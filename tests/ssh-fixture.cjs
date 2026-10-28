const { Server, utils } = require('ssh2');
// Native SEC1 encoding avoids ssh2's test-key generator stripping legitimate
// leading zero bytes from random Ed25519 public keys (roughly 1 in 256 keys).
const key = () => require('node:crypto').generateKeyPairSync('ec',{namedCurve:'prime256v1',privateKeyEncoding:{type:'sec1',format:'pem'}}).privateKey;
async function startServer(hostKey = key(), options = {}) {
  const clients = new Set();
  const server = new Server({ hostKeys: [hostKey] }, client => {
    clients.add(client); client.on('error', () => {}); client.on('close', () => clients.delete(client));
    client.on('authentication', ctx => {
      if (options.publicKey && ctx.method === 'publickey' && ctx.username === 'tester') {
        const parsed = utils.parseKey(options.publicKey); if (!(parsed instanceof Error) && parsed.getPublicSSH().equals(ctx.key.data) && (!ctx.signature || parsed.verify(ctx.blob, ctx.signature, ctx.hashAlgo) === true)) { ctx.accept(); return; }
      }
      if (ctx.method === 'password' && ctx.username === 'tester' && ctx.password === 'test-password') ctx.accept(); else ctx.reject(['password']);
    });
    if(options.forwarding)client.on('ready',()=>require('./forward-fixture.cjs').attachForwarding(client,options));
    client.on('ready', () => client.on('session', accept => {
      const session = accept();
      if (options.root) require('./sftp-fixture.cjs').attachSFTP(session, options.root);
      let hasPTY = false;
      session.on('pty', accept => { hasPTY = true; accept(); });
      session.on('window-change', accept => accept?.());
      session.on('shell', accept => { const stream = accept(); stream.write('Local integration SSH server\r\n$ '); stream.on('data', data => stream.write(data)); });
      session.on('exec', (accept, _reject, info) => {
        const stream = accept(); stream.on('error', () => {});
        if (info.command === 'cat /etc/os-release 2>/dev/null || uname -s') { stream.write('ID=ubuntu\nID_LIKE=debian\n'); stream.exit(0); stream.end(); return; }
        if (options.directExec && info.command.startsWith('python3 -u -c ')) {
          const child = require('node:child_process').spawn('/bin/sh', ['-c', info.command], { stdio: ['pipe', 'pipe', 'pipe'] });
          child.stdin.on('error', () => {});
          stream.on('data', chunk => child.stdin.write(chunk)); stream.on('end', () => child.stdin.end());
          child.stdout.on('data', chunk => stream.write(chunk)); child.stderr.on('data', chunk => stream.stderr.write(chunk));
          child.on('close', code => { stream.exit(code || 0); stream.end(); });
          stream.on('close', () => child.stdin.end()); return;
        }
        if (info.command === 'confirm-test') {
          if (!hasPTY) { stream.write('PTY required\n'); stream.exit(2); stream.end(); return; }
          stream.write('Continue? [y/N] ');
          let input = '';
          stream.on('data', chunk => {
            input += chunk.toString();
            if (/[\r\n]/.test(input)) { stream.write(input.trim() === 'y' ? '\r\nConfirmed\r\n' : '\r\nRejected\r\n'); stream.exit(input.trim() === 'y' ? 0 : 1); stream.end(); }
          });
          return;
        }
        if (info.command === 'sleep-forever') return;
        if (info.command === 'large-output') stream.write(Buffer.alloc(300000, 65));
        else if (info.command === 'fail-test') stream.stderr.write('expected test error\n');
        else stream.write(`executed: ${info.command}\n`);
        stream.exit(info.command === 'fail-test' ? 7 : 0); stream.end();
      });
    }));
  });
  await new Promise(resolve => server.listen(0, '127.0.0.1', resolve));
  return { port: server.address().port, hostKey, close: async () => { for (const c of clients) c.end(); await new Promise(resolve => server.close(resolve)); } };
}
module.exports = { startServer, key };
