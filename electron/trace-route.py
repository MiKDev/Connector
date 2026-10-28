"""Unprivileged Linux ICMP trace using the kernel ping socket and error queue.
No shell, raw-socket capability, or third-party Python package is used.
"""
import socket
import struct
import sys
import time
import select


def main():
    host, hops, wait = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]) / 1000
    address = socket.gethostbyname(host)
    print(f'Trace to {host} ({address}), {hops} hops, ICMP / IPv4', flush=True)
    for ttl in range(1, hops + 1):
        # New socket avoids stale time-exceeded packets from previous hops.
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as probe:
            probe.setsockopt(socket.SOL_IP, socket.IP_TTL, ttl)
            probe.setsockopt(socket.SOL_IP, 11, 1)  # IP_RECVERR
            probe.setblocking(False)
            probe.connect((address, 0))
            started = time.monotonic()
            probe.send(struct.pack('!BBHHH', 8, 0, 0, 0, ttl) + b'Connector trace')
            deadline = started + wait
            reached = False
            reply = '*'
            while time.monotonic() < deadline:
                select.select([probe], [], [probe], max(0, deadline - time.monotonic()))
                try:
                    data, source = probe.recvfrom(4096)
                    if data and data[0] == 0:
                        reply = source[0]
                        reached = True
                        break
                except (BlockingIOError, OSError):
                    pass
                try:
                    _, controls, _, _ = probe.recvmsg(4096, 512, socket.MSG_ERRQUEUE)
                    for level, kind, payload in controls:
                        if level == socket.SOL_IP and kind == 11 and len(payload) >= 24:
                            reply = socket.inet_ntoa(payload[20:24])
                            if payload[5] == 3:
                                reply += ' !unreachable'
                    break
                except (BlockingIOError, OSError):
                    pass
            elapsed = (time.monotonic() - started) * 1000
            print(f'{ttl:2}  {reply}' + (f'  {elapsed:.1f} ms' if reply != '*' else ''), flush=True)
            if reached or '!unreachable' in reply:
                return


if __name__ == '__main__':
    try:
        main()
    except PermissionError:
        sys.exit('Linux denied ICMP ping sockets. Enable the OS ping_group_range for this user.')
    except Exception as error:
        sys.exit(str(error))
