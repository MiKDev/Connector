#!/usr/bin/env python3
"""Ephemeral VPN gateway; network/kernel changes are confined to this guest."""
import concurrent.futures
import glob
import ipaddress
import json
import os
import secrets
import select
import socket
import struct
import subprocess
import threading
import time

CONTROL = None
WRITE_LOCK = threading.Lock()
READY, STOP = threading.Event(), threading.Event()
SOCKET_LOCK = threading.Lock()
SOCKETS, CHILDREN = set(), []
PROFILE, AUTH, DNS = {}, {}, []
MARK = 66

def event(name, **values):
    with WRITE_LOCK:
        CONTROL.write((json.dumps(dict(event=name, **values)) + '\n').encode())

def run(args, check=True):
    result = subprocess.run(args, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=25)
    if check and result.returncode:
        raise RuntimeError('Guest network command failed: ' + args[0])
    return result

def private_file(name, value):
    os.makedirs(os.path.dirname(name), mode=0o700, exist_ok=True)
    with os.fdopen(os.open(name, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600), 'w') as handle:
        handle.write(value)
    os.chmod(name, 0o600)

def quoted(value):
    value = str(value)
    if any(char in value for char in ('\n', '\r', '\x00')):
        raise RuntimeError('Invalid configuration text')
    return '"' + value.replace('\\', '\\\\').replace('"', '\\"') + '"'

def drop_streams():
    READY.clear()
    with SOCKET_LOCK:
        items = list(SOCKETS)
    for item in items:
        try:
            item.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        item.close()

def ppp_active():
    result = run(['ip', '-j', '-4', 'address', 'show', 'dev', 'ppp0'], False)
    try:
        return not result.returncode and any(item.get('addr_info') for item in json.loads(result.stdout))
    except ValueError:
        return False

def secure_active():
    if PROFILE.get('protocol') == 'l2tp':
        return True
    result = run(['ipsec', 'status', 'connector'], False)
    return b'ESTABLISHED' in result.stdout and b'INSTALLED' in result.stdout

def read_dns():
    if PROFILE.get('dns'):
        return PROFILE['dns']
    try:
        return [line.split()[1] for line in open('/etc/ppp/resolv.conf') if line.startswith('nameserver ') and ipaddress.ip_address(line.split()[1]).version == 4]
    except (OSError, ValueError):
        return []

def vpn_socket(kind=socket.SOCK_STREAM):
    if not READY.is_set():
        raise OSError('VPN is not ready')
    connection = socket.socket(socket.AF_INET, kind)
    try:
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b'ppp0\0')
        connection.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
        connection.settimeout(15)
        return connection
    except Exception:
        connection.close()
        raise

def resolve_name(host):
    try:
        literal = ipaddress.ip_address(host)
        if literal.version != 4:
            raise OSError('IPv6 VPN egress is not enabled')
        return [str(literal)]
    except ValueError:
        pass
    if not DNS:
        raise OSError('Configure VPN DNS or enable peer DNS')
    labels = host.rstrip('.').encode('ascii').split(b'.')
    if any(not label or len(label) > 63 for label in labels):
        raise OSError('Invalid DNS name')
    number = secrets.randbelow(65536)
    question = b''.join(bytes([len(label)]) + label for label in labels) + b'\0\0\1\0\1'
    packet = struct.pack('!HHHHHH', number, 0x100, 1, 0, 0, 0) + question
    def skip_name(data, offset):
        for _ in range(128):
            size = data[offset]
            if not size: return offset + 1
            if size & 0xc0 == 0xc0: return offset + 2
            if size > 63: raise ValueError('Malformed DNS name')
            offset += 1 + size
        raise ValueError('Malformed DNS name')
    for resolver in DNS:
        connection = vpn_socket(socket.SOCK_DGRAM)
        try:
            connection.connect((resolver, 53)); connection.send(packet); data = connection.recv(4096)
            response_id, flags, questions, answers, _, _ = struct.unpack_from('!HHHHHH', data)
            if response_id != number or not flags & 0x8000 or flags & 0x20f: continue
            offset, values = 12, []
            for _ in range(questions): offset = skip_name(data, offset) + 4
            for _ in range(answers):
                offset = skip_name(data, offset)
                record_type, record_class, _, size = struct.unpack_from('!HHIH', data, offset); offset += 10
                if record_type == 1 and record_class == 1 and size == 4: values.append(socket.inet_ntoa(data[offset:offset + 4]))
                offset += size
            if values: return list(dict.fromkeys(values))
        except (OSError, ValueError, IndexError, struct.error): pass
        finally: connection.close()
    raise OSError('VPN DNS resolution failed')

def exact(connection, size):
    data = bytearray()
    while len(data) < size:
        part = connection.recv(size - len(data))
        if not part: raise OSError('Connection closed')
        data.extend(part)
    return bytes(data)

def proxy_client(client):
    remote = None
    with SOCKET_LOCK: SOCKETS.add(client)
    try:
        client.settimeout(20); version, count = exact(client, 2); methods = exact(client, count)
        if version != 5 or 2 not in methods: client.sendall(b'\5\xff'); return
        client.sendall(b'\5\2'); version, count = exact(client, 2); user = exact(client, count); password = exact(client, exact(client, 1)[0])
        if version != 1 or not secrets.compare_digest(user, AUTH['username'].encode()) or not secrets.compare_digest(password, AUTH['password'].encode()):
            client.sendall(b'\1\1'); return
        client.sendall(b'\1\0'); version, command, reserved, address_type = exact(client, 4)
        if version != 5 or command != 1 or reserved: raise OSError('Only TCP CONNECT is supported')
        if address_type == 1: host = socket.inet_ntoa(exact(client, 4))
        elif address_type == 3: host = exact(client, exact(client, 1)[0]).decode('ascii')
        else: raise OSError('VPN egress currently supports IPv4 and DNS names')
        port = struct.unpack('!H', exact(client, 2))[0]
        networks = [ipaddress.ip_network(value) for value in PROFILE['allowedCidrs']]
        allowed = [value for value in resolve_name(host) if any(ipaddress.ip_address(value) in network for network in networks)]
        if not allowed: raise OSError('Destination outside VPN allowed prefixes')
        for value in allowed:
            try:
                remote = vpn_socket(); remote.connect((value, port)); break
            except OSError:
                if remote: remote.close()
                remote = None
        if not remote: raise OSError('VPN destination unavailable')
        with SOCKET_LOCK: SOCKETS.add(remote)
        client.sendall(b'\5\0\0\1\0\0\0\0\0\0'); client.settimeout(None); remote.settimeout(None)
        while READY.is_set() and not STOP.is_set():
            readable, _, _ = select.select([client, remote], [], [], 1)
            for source in readable:
                data = source.recv(65536)
                if not data: return
                (remote if source is client else client).sendall(data)
    except (OSError, ValueError, KeyError):
        try: client.sendall(b'\5\4\0\1\0\0\0\0\0\0')
        except OSError: pass
    finally:
        with SOCKET_LOCK: SOCKETS.discard(client); SOCKETS.discard(remote)
        client.close()
        if remote: remote.close()

def start_proxy():
    listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); listener.bind(('10.0.2.15', 1080)); listener.listen(64); listener.settimeout(1)
    pool = concurrent.futures.ThreadPoolExecutor(max_workers=64)
    while not STOP.is_set():
        try:
            connection, _ = listener.accept()
            with SOCKET_LOCK: full = len(SOCKETS) >= 120
            if full or not READY.is_set(): connection.close()
            else: pool.submit(proxy_client, connection)
        except socket.timeout: pass
    listener.close(); pool.shutdown(wait=False, cancel_futures=True)

def start_vpn(message):
    global PROFILE, AUTH, DNS
    PROFILE, AUTH = message['profile'], message['proxy']; event('phase', phase='configuring')
    run(['ip', 'rule', 'add', 'fwmark', str(MARK), 'table', '100', 'priority', '100'])
    run(['ip', 'route', 'add', 'unreachable', 'default', 'table', '100', 'metric', '32767'])
    run(['iptables', '-A', 'OUTPUT', '-m', 'mark', '--mark', str(MARK), '!', '-o', 'ppp0', '-j', 'REJECT'])
    if message.get('testLink'):
        run(['ip', 'link', 'set', 'eth1', 'up']); run(['ip', 'address', 'add', message['testLink'], 'dev', 'eth1'])
    peer = socket.gethostbyname(PROFILE['gateway']); ipaddress.IPv4Address(peer)
    user, password = quoted(PROFILE['username']), quoted(message['password'])
    private_file('/etc/ppp/chap-secrets', user + ' * ' + password + ' *\n'); private_file('/etc/ppp/pap-secrets', user + ' * ' + password + ' *\n')
    auth_method = PROFILE.get('authMethod', 'mschapv2')
    private_file('/run/ppp.log', '')
    options = ['noauth', 'ipcp-accept-local', 'ipcp-accept-remote', 'noipdefault', 'nodefaultroute', 'usepeerdns', 'hide-password', 'novj', 'nobsdcomp', 'nodeflate', 'persist', 'maxfail 0', 'lcp-echo-interval 5', 'lcp-echo-failure 3', 'mtu ' + str(PROFILE['mtu']), 'mru ' + str(PROFILE['mtu']), 'user ' + user]
    if auth_method == 'mschapv2': options += ['refuse-pap', 'refuse-chap', 'refuse-mschap', 'refuse-eap']
    elif auth_method == 'pap': options += ['refuse-chap', 'refuse-mschap', 'refuse-mschap-v2', 'refuse-eap']
    private_file('/run/ppp-options', '\n'.join(options) + '\n')
    with open('/run/ppp-options', 'a') as handle: handle.write('logfile /run/ppp.log\n')
    if PROFILE['protocol'] != 'l2tp':
        private_file('/etc/strongswan.d/charon/bypass-lan.conf', 'bypass-lan { load = no }\n')
        event('phase', phase='ipsec'); remote_id = quoted(PROFILE['remoteId']) if PROFILE.get('remoteId') else '%any'
        local_address = json.loads(run(['ip','-j','route','get',peer]).stdout)[0].get('prefsrc')
        if not local_address: raise RuntimeError('Cannot determine the VPN endpoint transport source address')
        private_file('/etc/ipsec.conf', '\n'.join(['config setup', ' uniqueids=no', 'conn connector', ' keyexchange=ikev1', ' type=transport', ' authby=secret', ' left=' + local_address, ' leftprotoport=17/1701', ' right=' + peer, ' rightprotoport=17/1701', ' rightid=' + remote_id, ' forceencaps=yes', ' ike=' + PROFILE['ike'], ' esp=' + PROFILE['esp'], ' dpdaction=clear', ' dpddelay=10s', ' keyingtries=1', ' auto=add', '']))
        private_file('/etc/ipsec.secrets', '%any ' + peer + ' : PSK 0x' + message['psk'].encode().hex() + '\n')
        run(['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '1701', '-m', 'policy', '--dir', 'out', '--pol', 'ipsec', '-j', 'ACCEPT'])
        run(['iptables', '-A', 'OUTPUT', '-p', 'udp', '--dport', '1701', '-j', 'DROP'])
        log = os.open('/run/ipsec.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        CHILDREN.append(subprocess.Popen(['ipsec', 'start', '--nofork'], stdout=log, stderr=log)); os.close(log); time.sleep(1)
        if run(['ipsec', 'up', 'connector'], False).returncode: raise RuntimeError('IPsec negotiation failed. Check PSK, gateway identity and IKE/ESP proposals.')
    event('phase', phase='l2tp')
    private_file('/etc/xl2tpd/xl2tpd.conf', '[global]\nport = 1701\n[lac connector]\nlns = ' + peer + '\npppoptfile = /run/ppp-options\nlength bit = yes\nautodial = yes\nredial = yes\nredial timeout = 5\n')
    os.makedirs('/run/xl2tpd', exist_ok=True)
    log = os.open('/run/l2tp.log', os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    CHILDREN.append(subprocess.Popen(['xl2tpd', '-D', '-c', '/etc/xl2tpd/xl2tpd.conf'], stdout=log, stderr=log)); os.close(log)
    start, online = time.monotonic(), False
    while not STOP.wait(1):
        active = ppp_active() and secure_active()
        if active and not online:
            run(['ip', 'route', 'replace', 'default', 'dev', 'ppp0', 'table', '100', 'metric', '1']); DNS = read_dns(); READY.set(); online = True; event('ready', dns=DNS, interface='ppp0')
        elif not active and online:
            online = False; drop_streams(); run(['ip', 'route', 'del', 'default', 'dev', 'ppp0', 'table', '100', 'metric', '1'], False); event('down', reason='VPN link or IPsec policy lost; dependent connections closed')
        if not online and time.monotonic() - start > 90: raise RuntimeError('L2TP/PPP did not become ready. Check authentication and server settings.')

def configure(message):
    try: start_vpn(message)
    except Exception as error:
        drop_streams(); event('failed', reason=str(error))

def control_port():
    for _ in range(300):
        for name in glob.glob('/sys/class/virtio-ports/*/name'):
            if open(name).read().strip() == 'org.connector.vpn': return '/dev/' + name.split('/')[-2]
        time.sleep(0.1)
    raise RuntimeError('Control port unavailable')

def main():
    global CONTROL
    CONTROL = open(control_port(), 'r+b', buffering=0); event('booted', version=1); configured = False
    while not STOP.is_set():
        line = CONTROL.readline(65536)
        if not line: break
        message = json.loads(line)
        if message.get('command') == 'ping': event('pong')
        elif message.get('command') == 'test-server' and os.path.isfile('/opt/connector/test-server.py'):
            import importlib.util
            spec = importlib.util.spec_from_file_location('test_server','/opt/connector/test-server.py'); module = importlib.util.module_from_spec(spec); spec.loader.exec_module(module)
            threading.Thread(target=module.start,args=(message,event,run,private_file,CHILDREN),daemon=True).start()
        elif message.get('command') == 'diagnose' and os.path.isfile('/opt/connector/test-server.py'):
            values = {}
            for filename in glob.glob('/run/*log'):
                try: values[filename] = open(filename).read()[-12000:]
                except OSError: pass
            values['ipsec'] = run(['ipsec','statusall'],False).stdout.decode(errors='replace')
            values['network'] = run(['ip','-j','address'],False).stdout.decode(errors='replace')
            event('diagnostics',logs=values)
        elif message.get('command') == 'test-drop-vpn' and os.path.isfile('/opt/connector/test-server.py'):
            run(['ipsec','down','connector'],False)
        elif message.get('command') == 'start' and not configured:
            configured = True; threading.Thread(target=start_proxy, daemon=True).start(); threading.Thread(target=configure, args=(message,), daemon=True).start()
        elif message.get('command') == 'stop': break
    STOP.set(); drop_streams()
    for child in CHILDREN:
        try: child.terminate()
        except OSError: pass
    os.sync(); os.execl('/bin/busybox', 'busybox', 'poweroff', '-f')

if __name__ == '__main__': main()
