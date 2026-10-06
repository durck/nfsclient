"""Probe native AUTH_TLS/ALPN with Python TLS; never send an NFS operation."""
import argparse
import hashlib
import json
import socket
import ssl
import struct


def receive(connection, count):
    data = bytearray()
    while len(data) < count:
        part = connection.recv(count - len(data))
        if not part:
            raise ValueError('truncated AUTH_TLS response')
        data.extend(part)
    return bytes(data)


def probe(host, port, ca, cert, key):
    context = ssl.create_default_context(cafile=ca)
    context.minimum_version = ssl.TLSVersion.TLSv1_3
    context.set_alpn_protocols(['sunrpc'])
    context.load_cert_chain(cert, key)
    with socket.create_connection((host, port), timeout=5) as connection:
        xid = 0x4E465354
        call = struct.pack('!10I', xid, 0, 2, 100003, 4, 0, 7, 0, 0, 0)
        connection.sendall(struct.pack('!I', 0x80000000 | len(call)) + call)
        marker, = struct.unpack('!I', receive(connection, 4))
        if not marker & 0x80000000 or not 24 <= (marker & 0x7fffffff) <= 1024:
            raise ValueError('unexpected AUTH_TLS record framing')
        reply = receive(connection, marker & 0x7fffffff)
        expected = struct.pack('!5I', xid, 1, 0, 0, 8) + b'STARTTLS' + struct.pack('!I', 0)
        if reply != expected:
            raise ValueError('native server did not acknowledge AUTH_TLS')
        with context.wrap_socket(connection, server_hostname=host) as secured:
            alpn = secured.selected_alpn_protocol()
            return dict(host=host, port=port, certificate_verified=True,
                        certificate_sha256=hashlib.sha256(secured.getpeercert(binary_form=True)).hexdigest(),
                        tls_version=secured.version(), cipher=secured.cipher()[0],
                        alpn=alpn, rpc_tls_ready=alpn == 'sunrpc', nfs_operations_sent=0)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--host', required=True)
    parser.add_argument('--port', type=int, default=2049)
    parser.add_argument('--ca', required=True)
    parser.add_argument('--cert', required=True)
    parser.add_argument('--key', required=True)
    args = parser.parse_args()
    print(json.dumps(probe(args.host, args.port, args.ca, args.cert, args.key), indent=2))
