"""Audit client grants/COPY/callbacks and actual server-to-server READ payloads."""
import hashlib
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'offload'))
from audit_offload import XDR, messages, rpc_body


def pairs(path):
    result = {}
    for transport, key, data in messages(path):
        if transport != 'tcp':
            continue
        xid, direction = struct.unpack('!II', data[:8])
        origin = key if direction == 0 else (key[2], key[3], key[0], key[1])
        pair = result.setdefault((origin, xid), {})
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    return result


def locations(d):
    count = d.u32()
    assert 0 < count <= 64
    result = []
    for _ in range(count):
        assert d.u32() == 3, 'nonliteral source address forwarded'
        result.append((d.opaque(), d.opaque()))
    return result


def result(pair, operations):
    assert 1 in pair, 'missing RPC result'
    r = rpc_body(pair[1], True)
    assert r.u32() == 0
    r.opaque()
    assert r.u32() == len(operations)+1 and r.u32() == 53 and r.u32() == 0
    r.take(36)
    for op in operations:
        assert r.u32() == op and r.u32() == 0
    return r


def foreground(pair):
    if 0 not in pair:
        return None
    program, version, procedure, d = rpc_body(pair[0])
    if (program, version, procedure) != (100003, 4, 1):
        return None
    d.opaque()
    if d.u32() != 2:
        return None
    count = d.u32()
    if count < 3 or d.u32() != 53:
        return None
    d.take(32)
    if d.u32() != 22:
        return None
    return count, d.opaque(), d


def audit(root, expected=12):
    grants, revoked = {}, set()
    for pair in pairs(root/'source/client-network.pcap').values():
        parsed = foreground(pair)
        if parsed is None:
            continue
        count, fh, d = parsed
        if count != 3:
            continue
        op = d.u32()
        if op == 61:
            d.take(16)
            assert d.u32() == 3 and d.opaque() == b'tcp' and d.opaque() == b'10.78.0.2.8.1'
            d.done()
            r = result(pair, [22, 61])
            assert r.u64() > 0 and r.u32() < 1000000000
            token = r.take(16)
            addresses = locations(r)
            r.done()
            assert token not in grants and addresses == [(b'tcp', b'10.77.1.15.8.1')]
            grants[token] = fh, addresses
        elif op == 66:
            token = d.take(16)
            d.done()
            result(pair, [22,66]).done()
            assert token not in revoked
            revoked.add(token)
    copies, callbacks, used = {}, [], set()
    for (origin, xid), pair in pairs(root/'destination/client-network.pcap').items():
        if 0 not in pair:
            continue
        program, version, procedure, d = rpc_body(pair[0])
        if (program, version, procedure) == (0x40000001, 1, 1):
            d.opaque(); assert d.u32() == 2
            d.u32(); count=d.u32()
            assert d.u32() == 11
            d.take(16); d.u32(); d.take(12)
            for _ in range(d.u32()):
                d.take(16)
                for _ in range(d.u32()): d.take(8)
            if count != 2 or d.u32() != 15:
                continue
            fh, job = d.opaque(), d.take(16)
            assert d.u32() == 0 and d.u32() == 0
            length, stable, verifier = d.u64(), d.u32(), d.take(8)
            d.done()
            assert 1 in pair
            reply = rpc_body(pair[1], True)
            status = reply.u32()
            if status == 0:
                callbacks.append((origin, fh, job, length, stable))
            else:
                assert status in (10008,10068)
            continue
        parsed = foreground(pair)
        if parsed is None:
            continue
        count, source, d = parsed
        if count != 5 or d.u32() != 32:
            continue
        assert d.u32() == 22
        destination = d.opaque()
        if d.u32() != 60:
            continue
        token = d.take(16); d.take(16)
        offset, destination_offset, length = d.u64(), d.u64(), d.u64()
        assert d.u32() == 1 and d.u32() == 0
        addresses = locations(d)
        d.done()
        assert token in grants and grants[token] == (source, addresses) and token not in used
        used.add(token)
        assert (offset,destination_offset,length) in [(65536,32768,131072),(0,262144,65536)]
        r = result(pair, [22,32,22,60])
        assert r.u32() == 1, 'expected actual asynchronous inter-server COPY'
        job = r.take(16)
        assert r.u64() <= length and r.u32() <= 2
        r.take(8)
        assert r.u32() == 1 and r.u32() == 0
        r.done()
        reverse = (origin[2],origin[3],origin[0],origin[1])
        key = reverse,destination,job
        assert key not in copies
        copies[key] = token,offset,length
    completed = set()
    for origin,fh,job,length,stable in callbacks:
        key = origin,fh,job
        assert key in copies and copies[key][2] == length and stable == 2
        completed.add(key)
    # The independent data-plane capture proves data traveled between kernels.
    source_bytes = bytes((i*31+i//257)%251 for i in range(262144))
    intervals, read_count = {}, 0
    for pair in pairs(root/'source/server-network.pcap').values():
        parsed = foreground(pair)
        if parsed is None:
            continue
        count,fh,d = parsed
        if d.u32() != 25:
            continue
        token,offset,requested = d.take(16),d.u64(),d.u32()
        matches = [key for key in used if key[4:] == token[4:] and grants[key][0] == fh]
        assert len(matches) == 1, 'READ without a unique COPY authorization'
        assert 1 in pair
        r = rpc_body(pair[1],True)
        assert r.u32() == 0
        r.opaque(); assert r.u32() == count and r.u32() == 53 and r.u32() == 0
        r.take(36)
        for op in (22,25): assert r.u32() == op and r.u32() == 0
        assert r.u32() in (0,1)
        size = r.u32()
        assert 0 < size <= requested <= 1048576
        payload = r.take(size)
        assert payload == source_bytes[offset:offset+size], 'server READ payload mismatch'
        intervals.setdefault(matches[0],[]).append((offset,offset+size))
        read_count += 1
    for token,offset,length in copies.values():
        covered = offset
        for start,end in sorted(intervals.get(token,[])):
            if start <= covered: covered = max(covered,end)
        assert covered >= offset+length, 'COPY lacks captured source READ coverage'
    assert len(copies) == len(completed) == len(used) == expected
    assert len(grants) == len(revoked) == expected*3//2 and revoked == set(grants)
    return dict(passed=True, grants=len(grants), confirmed_revocations=len(revoked),
                asynchronous_copies=len(copies), completed_callbacks=len(completed),
                refused_source_grants=len(grants)-len(used), server_to_server_reads=read_count,
                copied_bytes=sum(value[2] for value in copies.values()))


def native(root):
    source=bytes((i*31+i//257)%251 for i in range(262144))
    destination=bytearray(327680)
    destination[:32768]=b'D'*32768
    destination[32768:163840]=source[65536:196608]
    destination[262144:]=source[:65536]
    expected={'src':hashlib.sha256(source).hexdigest(),'dst':hashlib.sha256(destination).hexdigest()}
    found=set()
    for role,kind in [('source','src'),('destination','dst')]:
        names={f'copyfrom-{os}-{mode}-{kind}' for os in ('windows','linux') for mode in ('session','locked','cli')}
        for line in (root/role/'native-sha256.txt').read_text().splitlines():
            digest,path=line.split(maxsplit=1)
            name=pathlib.PurePosixPath(path).name
            assert name in names and name not in found and digest==expected[kind], name
            found.add(name)
        assert names <= found
    assert len(found)==12
    return dict(passed=True, native_files=len(found), sha256=expected)


if __name__ == '__main__':
    root=pathlib.Path(sys.argv[1])
    print(json.dumps(dict(wire=audit(root),native=native(root)),indent=2))
