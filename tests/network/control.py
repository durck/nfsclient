"""Disposable network namespace controller, published on loopback only.

Requires NET_ADMIN in this container, never host networking. Native UNFS3 owns
all RPC processing; the controller only changes the container MTU/reply filter.
"""
import http.server
import json
import pathlib
import subprocess
import collections
import socket
import struct
import threading

wire = collections.Counter()
wire_lock = threading.Lock()


def capture():
    nfs_fragments = set()
    with socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(3)) as sock:
        sock.bind(('eth0', 0))
        while True:
            packet, address = sock.recvfrom(65536)
            if packet[12:14] != b'\x08\x00' or len(packet) < 34:
                continue
            ip = packet[14:]
            header = (ip[0] & 15) * 4
            direction = 'out' if address[2] == socket.PACKET_OUTGOING else 'in'
            offset = struct.unpack('!H', ip[6:8])[0] & 0x1fff
            more = bool(struct.unpack('!H', ip[6:8])[0] & 0x2000)
            if direction == 'out' and ip[9] == 17 and (offset or more):
                flow = (ip[12:20], ip[4:6])
                if offset == 0 and len(ip) >= header+8 and struct.unpack('!H', ip[header:header+2])[0] == 2049:
                    nfs_fragments.add(flow)
                if flow in nfs_fragments:
                    with wire_lock:
                        wire['out:nfs_udp_fragments'] += 1
                    if not more:
                        nfs_fragments.remove(flow)
            key = None
            if ip[9] == 1 and len(ip) >= header+8:
                key = f'{direction}:icmp:{ip[header]}:{ip[header+1]}'
            elif ip[9] == 17 and not offset and len(ip) >= header+32:
                src, dst = struct.unpack('!HH', ip[header:header+4])
                if 2049 not in (src, dst):
                    continue
                rpc = ip[header+8:]
                kind = struct.unpack('!I', rpc[4:8])[0]
                if kind == 0 and len(rpc) >= 24:
                    prog, version, proc = struct.unpack('!III', rpc[12:24])
                    key = f'{direction}:call:{prog}:{version}:{proc}'
                elif kind == 1:
                    key = f'{direction}:reply'
            if key:
                with wire_lock:
                    wire[key] += 1


def run(*args):
    return subprocess.check_output(args, text=True)


def snapshot():
    lines = pathlib.Path('/proc/net/snmp').read_text().splitlines()
    fields = {}
    for names, values in zip(lines[::2], lines[1::2]):
        if names.startswith('Ip:'):
            fields = dict(zip(names.split()[1:], map(int, values.split()[1:])))
    rules = run('iptables', '-L', 'NVTEST', '-n', '-v', '-x').splitlines()[2:]
    dropped = sum(int(line.split()[0]) for line in rules if 'DROP' in line)
    with wire_lock:
        packets = dict(wire)
    return dict(ip=fields, dropped=dropped, wire=packets,
                mtu=int(pathlib.Path('/sys/class/net/eth0/mtu').read_text()))


class Control(http.server.BaseHTTPRequestHandler):
    def do_GET(self):
        if self.path not in ('/status', '/normal/900', '/normal/1500', '/drop'):
            self.send_error(404)
            return
        if self.path != '/status':
            run('iptables', '-F', 'NVTEST')
            if self.path == '/drop':
                run('iptables', '-A', 'NVTEST', '-p', 'udp', '--sport', '2049', '-j', 'DROP')
            else:
                run('ip', 'link', 'set', 'eth0', 'mtu', self.path.rsplit('/', 1)[1])
        body = json.dumps(snapshot()).encode()
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(body)))
        self.end_headers()
        self.wfile.write(body)


if __name__ == '__main__':
    run('iptables', '-N', 'NVTEST')
    run('iptables', '-A', 'OUTPUT', '-j', 'NVTEST')
    server = subprocess.Popen(['sh', '/start.sh'])
    threading.Thread(target=capture, daemon=True).start()
    try:
        http.server.HTTPServer(('0.0.0.0', 19877), Control).serve_forever()
    finally:
        server.terminate()
        server.wait(timeout=5)
