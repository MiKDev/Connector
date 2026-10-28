"""Disposable L2TP peer and TCP/DNS fixtures. Included only in test images."""
import socket
import struct
import subprocess
import threading
import time

def start(message, event, run, private_file, children):
    run(['ip','link','set','eth1','up'])
    run(['ip','address','add','198.18.0.1/24','dev','eth1'])
    user, password, psk = 'connector-test', 'connector-test-password', 'connector-test-psk'
    private_file('/etc/ppp/chap-secrets', '"' + user + '" * "' + password + '" *\n')
    private_file('/etc/ppp/pap-secrets', '"' + user + '" * "' + password + '" *\n')
    private_file('/run/server-ppp', 'auth\nname connector-server\nrequire-mschap-v2\nrefuse-pap\nrefuse-chap\nrefuse-mschap\nrefuse-eap\nms-dns 10.77.0.1\nmtu 1400\nmru 1400\nlogfile /run/server-ppp.log\ndebug\n')
    if message.get('ipsec'):
        private_file('/etc/strongswan.d/charon/bypass-lan.conf', 'bypass-lan { load = no }\n')
        private_file('/etc/ipsec.conf', 'config setup\n uniqueids=no\nconn testvpn\n keyexchange=ikev1\n type=transport\n authby=secret\n left=198.18.0.1\n leftprotoport=17/1701\n right=%any\n rightprotoport=17/%any\n ike=aes256-sha256-modp2048!\n esp=aes256-sha256!\n auto=add\n')
        private_file('/etc/ipsec.secrets', '%any : PSK 0x' + psk.encode().hex() + '\n')
        log = open('/run/server-ipsec.log','wb')
        children.append(subprocess.Popen(['ipsec','start','--nofork'],stdout=log,stderr=log))
        time.sleep(1)
    private_file('/etc/xl2tpd/xl2tpd.conf', '[global]\nport = 1701\n[lns default]\nip range = 10.77.0.10-10.77.0.20\nlocal ip = 10.77.0.1\nrequire authentication = yes\nname = connector-server\npppoptfile = /run/server-ppp\nlength bit = yes\n')
    log = open('/run/server-l2tp.log','wb')
    children.append(subprocess.Popen(['xl2tpd','-D','-c','/etc/xl2tpd/xl2tpd.conf'],stdout=log,stderr=log))
    def echo():
        listener = socket.socket(); listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1); listener.bind(('0.0.0.0',2222)); listener.listen()
        while True:
            client,_ = listener.accept()
            def reply(connection):
                with connection:
                    connection.sendall((message.get('tag','fixture')+'\n').encode())
                    while True:
                        data=connection.recv(65536)
                        if not data: return
                        connection.sendall(data)
            threading.Thread(target=reply,args=(client,),daemon=True).start()
    def dns():
        listener=socket.socket(socket.AF_INET,socket.SOCK_DGRAM); listener.bind(('0.0.0.0',53))
        while True:
            data,peer=listener.recvfrom(4096)
            answer=data[:2]+struct.pack('!HHHHH',0x8180,1,1,0,0)+data[12:]+b'\xc0\x0c'+struct.pack('!HHIH',1,1,30,4)+socket.inet_aton('10.77.0.1')
            listener.sendto(answer,peer)
    threading.Thread(target=echo,daemon=True).start(); threading.Thread(target=dns,daemon=True).start()
    event('server-ready',ipsec=bool(message.get('ipsec')))
