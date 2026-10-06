"""Audit a complete Ethernet/IPv4 NLM TEST capture without client code."""
import collections
import hashlib
import json
import pathlib
import struct
import sys


class XDR:
    def __init__(self, data):
        self.data, self.pos = data, 0

    def take(self, size):
        assert self.pos + size <= len(self.data), "truncated XDR"
        result = self.data[self.pos:self.pos + size]
        self.pos += size
        return result

    def u32(self):
        return struct.unpack("!I", self.take(4))[0]

    def u64(self):
        return struct.unpack("!Q", self.take(8))[0]

    def opaque(self):
        size = self.u32()
        assert size <= 4096, "oversized field"
        result = self.take(size)
        self.take(-size % 4)
        return result

    def done(self):
        assert self.pos == len(self.data), "trailing XDR"


def messages(path):
    data = path.read_bytes()
    assert data[:4] in (b"\xd4\xc3\xb2\xa1", b"\xa1\xb2\xc3\xd4")
    endian = "<" if data[:4] == b"\xd4\xc3\xb2\xa1" else ">"
    assert struct.unpack_from(endian + "I", data, 20)[0] == 1
    pos, streams = 24, collections.defaultdict(list)
    generations = {}
    finished = {}
    while pos < len(data):
        _, _, size, original = struct.unpack_from(endian + "IIII", data, pos)
        pos += 16
        packet = data[pos:pos + size]
        pos += size
        assert size == original == len(packet), "truncated capture"
        if packet[12:14] != b"\x08\x00":
            continue
        ip = packet[14:]
        assert not struct.unpack("!H", ip[6:8])[0] & 0x3FFF, "fragmented IP"
        ih = (ip[0] & 15) * 4
        payload = ip[ih:struct.unpack("!H", ip[2:4])[0]]
        if ip[9] not in (6, 17):
            continue
        sp, dp = struct.unpack("!HH", payload[:4])
        key = (ip[12:16].hex(), sp, ip[16:20].hex(), dp)
        if ip[9] == 17:
            length = struct.unpack("!H", payload[4:6])[0]
            assert length == len(payload)
            yield "udp", key, payload[8:]
        else:
            sequence = struct.unpack("!I", payload[4:8])[0]
            if payload[13] & 2:  # SYN, including SYN/ACK and identical retries.
                generations[key] = sequence
            body = payload[(payload[12] >> 4) * 4:]
            stream = (key, generations.get(key))
            # A post-FIN keepalive may probe the FIN sequence with one zero
            # byte. FIN consumes sequence space but is not RPC payload.
            if finished.get(stream) == sequence and body == b"\x00" and payload[13] == 0x10:
                continue
            if payload[13] & 1:
                finished[stream] = sequence + len(body)
            if body:
                streams[stream].append((sequence, body))
    for (key, _generation), chunks in streams.items():
        chunks.sort()
        start = current = chunks[0][0]
        combined = bytearray()
        for sequence, body in chunks:
            assert sequence <= current, "TCP gap"
            overlap = min(current - sequence, len(body))
            assert combined[sequence-start:sequence-start+overlap] == body[:overlap]
            combined.extend(body[overlap:])
            current += len(body) - overlap
        pos, fragment = 0, bytearray()
        while pos < len(combined):
            mark = struct.unpack_from("!I", combined, pos)[0]
            pos += 4
            size = mark & 0x7FFFFFFF
            assert pos + size <= len(combined), "truncated RPC record"
            fragment.extend(combined[pos:pos + size])
            pos += size
            if mark & 0x80000000:
                yield "tcp", key, bytes(fragment)
                fragment.clear()
        assert not fragment


def audit(path):
    pairs = collections.defaultdict(dict)
    for transport, key, data in messages(path):
        xid, direction = struct.unpack("!II", data[:8])
        assert direction in (0, 1)
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[(transport, flow, xid)]
        assert direction not in pair or pair[direction] == data, "changed retransmission"
        pair[direction] = data
    counts, holders, cookies = collections.Counter(), collections.Counter(), set()
    for (transport, _, _), pair in pairs.items():
        assert set(pair) == {0, 1}, "incomplete RPC exchange"
        call, reply = XDR(pair[0]), XDR(pair[1])
        call.take(8)
        assert call.u32() == 2
        program, version, procedure = call.u32(), call.u32(), call.u32()
        if program != 100021:
            assert program == 100000, "unexpected service in filtered capture"
            continue
        assert version in (1, 4) and procedure == 1, "unexpected NLM mutation/callback"
        assert call.u32() == 1
        cred = XDR(call.opaque())
        cred.u32()
        assert cred.opaque() == b"nfs-viewer"
        uid, gid = cred.u32(), cred.u32()
        assert uid in (0, 20001) and gid in (0, 20001)
        groups = cred.u32()
        assert groups <= 16
        for _ in range(groups):
            cred.u32()
        cred.done()
        assert call.u32() == 0 and call.opaque() == b""
        cookie, exclusive = call.opaque(), call.u32()
        assert len(cookie) == 16 and cookie not in cookies and exclusive in (0, 1)
        cookies.add(cookie)
        assert call.opaque()  # Numeric caller name.
        fh, owner, svid = call.opaque(), call.opaque(), call.u32()
        assert 0 < len(fh) <= 64 and len(owner) == 16 and svid > 0
        if version == 1:
            assert len(fh) == 32
        offset = call.u32() if version == 1 else call.u64()
        length = call.u32() if version == 1 else call.u64()
        call.done()
        reply.take(8)
        assert reply.u32() == 0
        reply.u32()
        reply.opaque()
        assert reply.u32() == 0 and reply.opaque() == cookie
        status = reply.u32()
        assert status in (0, 1)
        if status == 1:
            held_write, pid = reply.u32(), reply.u32()
            reply.opaque()
            start = reply.u32() if version == 1 else reply.u64()
            size = reply.u32() if version == 1 else reply.u64()
            assert (held_write, start, size) in ((1, 8, 8), (0, 16, 0), (1, (1 << 33)+7, 11))
            assert pid > 0 and (exclusive or held_write)
            assert (not size or offset < start + size) and (not length or start < offset + length)
            holders[f"{held_write}/{start}/{size}/pid={pid}"] += 1
        reply.done()
        counts[f"{transport}/v{version}/status{status}"] += 1
    assert len(cookies) == 304, f"expected 32 fixture profiles, got {len(cookies)} TEST calls"
    assert sum(holders.values()) == 88
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(), "test_calls": len(cookies),
            "matching_replies": len(cookies), "conflicts": sum(holders.values()),
            "only_nlm_test": True, "profiles": dict(counts), "native_holders": dict(holders)}


if __name__ == "__main__":
    print(json.dumps(audit(pathlib.Path(sys.argv[1])), indent=2))
