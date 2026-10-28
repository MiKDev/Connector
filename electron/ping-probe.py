"""Linux IPv4 ping via an unprivileged ICMP datagram socket."""
import socket
import struct
import sys
import time
import select


def main():
    host, count, wait = sys.argv[1], int(sys.argv[2]), int(sys.argv[3]) / 1000
    address = socket.gethostbyname(host)
    print(f'PING {host} ({address}), 32 bytes payload', flush=True)
    times = []
    for sequence in range(1, count + 1):
        started = time.monotonic()
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_ICMP) as probe:
            probe.setblocking(False)
            probe.connect((address, 0))
            probe.send(struct.pack('!BBHHH', 8, 0, 0, 0, sequence) + b'Connector ping'.ljust(32, b'.'))
            deadline = started + wait
            received = False
            while time.monotonic() < deadline:
                if not select.select([probe], [], [], max(0, deadline - time.monotonic()))[0]:
                    break
                try:
                    data, source = probe.recvfrom(4096)
                    if len(data) >= 8 and data[0] == 0 and struct.unpack('!H', data[6:8])[0] == sequence:
                        elapsed = (time.monotonic() - started) * 1000
                        times.append(elapsed)
                        print(f'{len(data)} bytes from {source[0]}: seq={sequence} time={elapsed:.2f} ms', flush=True)
                        received = True
                        break
                except BlockingIOError:
                    pass
            if not received:
                print(f'Request timeout: seq={sequence}', flush=True)
        if sequence < count:
            time.sleep(max(0, 1 - (time.monotonic() - started)))
    print(f'{count} transmitted, {len(times)} received, {(count-len(times))*100/count:.1f}% loss', flush=True)
    if times:
        print(f'RTT min/avg/max = {min(times):.2f}/{sum(times)/len(times):.2f}/{max(times):.2f} ms', flush=True)
    return 0 if times else 1


if __name__ == '__main__':
    try:
        sys.exit(main())
    except PermissionError:
        sys.exit('Linux denied ICMP ping sockets. Enable OS ping_group_range for this user.')
    except Exception as error:
        sys.exit(str(error))
