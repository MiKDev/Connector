"""Run on the source Linux server. Payload arrives on SSH stdin, never argv/disk.

Requires Python 3, OpenSSH scp >= 9 and a password-authenticated destination.
The local Unix-socket askpass broker keeps the borrowed password in memory.
"""
import json
import os
import re
import shutil
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading

cancelled = threading.Event()
child_lock = threading.Lock()
child = None


def emit(value):
    print(json.dumps(value), flush=True)


def stop_child():
    with child_lock:
        current = child
    if current and current.poll() is None:
        try:
            os.killpg(current.pid, signal.SIGTERM)
            current.wait(timeout=3)
        except subprocess.TimeoutExpired:
            try:
                os.killpg(current.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
        except ProcessLookupError:
            pass


def monitor(pending):
    # Any subsequent line, or SSH stdin EOF, revokes the operation.
    if not pending:
        # Do not leave a daemon holding a buffered Python stdin lock at exit.
        os.read(sys.stdin.fileno(), 1)
    cancelled.set()
    stop_child()


def read_payload():
    data = bytearray()
    while b'\n' not in data:
        chunk = os.read(sys.stdin.fileno(), 65536)
        if not chunk:
            raise RuntimeError('Missing transfer configuration')
        data.extend(chunk)
        if len(data) > 2 * 1024 * 1024:
            raise RuntimeError('Transfer configuration is too large')
    line, pending = bytes(data).split(b'\n', 1)
    return json.loads(line.decode('utf-8')), pending


def main():
    global child
    if os.name != 'posix':
        raise RuntimeError('Direct transfer requires a Linux/Unix source server')
    payload, pending = read_payload()
    password = payload.pop('password')
    if not shutil.which('scp') or not shutil.which('ssh'):
        raise RuntimeError('Install OpenSSH client (scp and ssh) on the source server')
    version = subprocess.run(['ssh', '-V'], capture_output=True, text=True, timeout=10)
    match = re.search(r'OpenSSH_(\d+)', version.stderr + version.stdout)
    if not match or int(match.group(1)) < 9:
        raise RuntimeError('Direct SFTP transfer requires OpenSSH 9 or newer on the source')
    def interrupted(_number, _frame):
        cancelled.set()
        threading.Thread(target=stop_child, daemon=True).start()

    for name in ('SIGHUP', 'SIGTERM', 'SIGINT'):
        if hasattr(signal, name):
            signal.signal(getattr(signal, name), interrupted)
    threading.Thread(target=monitor, args=(pending,), daemon=True).start()
    # A short /tmp path avoids the Unix-domain-socket pathname limit.
    with tempfile.TemporaryDirectory(prefix='connector-', dir='/tmp') as folder:
        os.chmod(folder, 0o700)
        known_hosts = os.path.join(folder, 'known_hosts')
        helper = os.path.join(folder, 'askpass')
        socket_path = os.path.join(folder, 'auth.sock')
        with open(known_hosts, 'w', encoding='utf-8') as handle:
            handle.write(payload['knownHost'] + '\n')
        os.chmod(known_hosts, 0o600)
        # The helper contains no credential. Only this UID can reach the socket.
        with open(helper, 'w', encoding='utf-8') as handle:
            handle.write('#!/usr/bin/env python3\nimport os,socket,sys\ns=socket.socket(socket.AF_UNIX)\ns.connect(os.environ["CONNECTOR_AUTH_SOCKET"])\ndata=bytearray()\nwhile True:\n b=s.recv(4096)\n if not b: break\n data.extend(b)\nsys.stdout.buffer.write(data)\ns.close()\n')
        os.chmod(helper, 0o700)
        broker = socket.socket(socket.AF_UNIX)
        broker.bind(socket_path)
        os.chmod(socket_path, 0o600)
        broker.listen(2)
        broker.settimeout(0.5)

        def serve_auth():
            while not cancelled.is_set():
                try:
                    connection, _ = broker.accept()
                    with connection:
                        connection.sendall(password.encode('utf-8') + b'\n')
                except socket.timeout:
                    continue
                except OSError:
                    break

        threading.Thread(target=serve_auth, daemon=True).start()
        environment = os.environ.copy()
        # Do not inherit forwarding, proxy, askpass or user SSH configuration.
        environment.pop('SSH_AUTH_SOCK', None)
        environment.update(SSH_ASKPASS=helper, SSH_ASKPASS_REQUIRE='force', DISPLAY='connector:0', CONNECTOR_AUTH_SOCKET=socket_path)
        host = payload['host']
        if ':' in host:
            host = '[' + host + ']'
        try:
            for index, item in enumerate(payload['files']):
                if cancelled.is_set():
                    raise RuntimeError('Transfer cancelled')
                source_stat = os.lstat(item['src'])
                if not stat.S_ISREG(source_stat.st_mode) or source_stat.st_size != item['size']:
                    raise RuntimeError('A source file changed after transfer planning')
                emit({'event': 'file', 'index': index})
                args = ['scp', '-F', '/dev/null', '-P', str(payload['port']),
                        '-o', 'StrictHostKeyChecking=yes', '-o', 'UserKnownHostsFile=' + known_hosts,
                        '-o', 'GlobalKnownHostsFile=/dev/null', '-o', 'PreferredAuthentications=password',
                        '-o', 'PubkeyAuthentication=no', '-o', 'KbdInteractiveAuthentication=no',
                        '-o', 'PasswordAuthentication=yes', '-o', 'NumberOfPasswordPrompts=1',
                        '-o', 'ProxyCommand=none', '-o', 'ProxyJump=none', '-o', 'IdentityAgent=none',
                        '-o', 'ConnectTimeout=20', '-o', 'ServerAliveInterval=15', '-o', 'ServerAliveCountMax=3',
                        '-o', 'User=' + payload['username'], '--', item['src'], host + ':' + item['dst']]
                with child_lock:
                    if cancelled.is_set():
                        raise RuntimeError('Transfer cancelled')
                    child = subprocess.Popen(args, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                             stderr=subprocess.PIPE, env=environment, start_new_session=True)
                # Drain stderr while keeping memory bounded. Never echo the payload.
                tail = bytearray()
                while True:
                    chunk = child.stderr.read(4096)
                    if not chunk:
                        break
                    tail.extend(chunk)
                    if len(tail) > 8192:
                        del tail[:-8192]
                code = child.wait()
                if cancelled.is_set():
                    raise RuntimeError('Transfer cancelled')
                if code:
                    raise RuntimeError(tail.decode('utf-8', errors='replace').strip() or 'scp failed')
                emit({'event': 'completed', 'index': index})
            emit({'event': 'done'})
        finally:
            cancelled.set()
            stop_child()
            broker.close()


try:
    main()
except Exception as error:
    # No passwords, configuration blobs or command arguments are logged.
    emit({'event': 'error', 'message': str(error)})
    sys.exit(1)
