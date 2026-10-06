"""Independently decode stock FreeBSD Flex reads and complete DS payload hashes."""
import argparse
import collections
import hashlib
import ipaddress
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / 'nlm/freebsd'))
from audit import XDR as BaseXDR, messages


class XDR(BaseXDR):
    def opaque(self):
        size = self.u32()
        assert size <= 2**20, 'oversized field'
        data = self.take(size)
        self.take(-size % 4)
        return data


def audit(capture, expected_hash, servers=("192.168.116.131",), runs=1):
    servers=tuple(str(ipaddress.IPv4Address(s)) for s in servers)
    assert 1<=len(servers)<=2 and len(set(servers))==len(servers) and runs in (1,2)
    pairs = collections.defaultdict(dict)
    destinations = {}
    for transport, key, raw in messages(capture):
        if transport != 'tcp' or 2049 not in (key[1], key[3]):
            continue
        xid, direction = struct.unpack('!II', raw[:8])
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[flow, xid]
        assert direction not in pair or pair[direction] == raw, 'changed replay'
        pair[direction] = raw
        if direction == 0:
            destinations[flow, xid] = key[2]
    counts = collections.Counter()
    handles,selected,devices = {},{},{}
    reads = collections.defaultdict(list)
    minors = set()
    for (flow, xid), pair in pairs.items():
        if 0 not in pair:
            continue
        c = XDR(pair[0]); c.take(8)
        if tuple(c.u32() for _ in range(4)) != (2, 100003, 4, 1):
            continue
        flavor, cred = c.u32(), XDR(c.opaque())
        if flavor != 1:
            continue
        cred.u32()
        if cred.opaque() != b'nfs-viewer':
            continue
        assert tuple(cred.u32() for _ in range(3)) == (25001, 25000, 0)
        cred.done()
        assert c.u32() == 0 and c.opaque() == b''
        c.opaque(); minor, total = c.u32(), c.u32()
        prefix, fh = [], None
        for index in range(total):
            code = c.u32()
            if code == 53:
                c.take(32); prefix.append(code)
            elif code == 22:
                fh = c.opaque(); prefix.append(code)
            else:
                break
        else:
            continue
        if code not in (25, 47, 50, 51):
            continue
        assert index == total-1 and 1 in pair, 'incomplete operation'
        r = XDR(pair[1]); r.take(8)
        assert r.u32() == 0
        r.u32(); r.opaque(); assert r.u32() == 0
        assert r.u32() == 0
        r.opaque(); assert r.u32() == total
        for op in prefix:
            assert r.u32() == op and r.u32() == 0
            if op == 53:
                r.take(36)
        assert r.u32() == code and r.u32() == 0
        server = str(ipaddress.ip_address(bytes.fromhex(destinations[flow, xid])))
        mds = server == '192.168.116.130'
        assert mds or server in servers
        counts[('mds_' if mds else 'ds_') + str(code)] += 1
        if mds:
            minors.add(minor)
            assert code != 25, 'MDS READ fallback'
        else:
            assert code == 25 and minor == 2, 'wrong DS protocol'
        if code == 50:
            assert c.u32() == 0 and c.u32() == 4 and c.u32() == 1
            assert c.u64() == 0 and c.u64() == 2**64-1 and c.u64() == 1
            c.take(16); assert c.u32() == 32768
            r.u32(); r.take(16); assert r.u32() == 1
            assert r.u64() == 0 and r.u64() == 2**64-1
            assert r.u32() == 1 and r.u32() == 4
            b = XDR(r.opaque())
            assert b.u64()==0 and b.u32()==len(servers)
            mirrors=[]
            for _ in servers:
                assert b.u32()==1
                device=b.take(16); efficiency=b.u32(); state=b.take(16)
                assert b.u32()==1; handle=b.opaque()
                b.opaque(); b.opaque()
                mirrors.append((efficiency,device,handle,state))
            # Python max preserves the first entry on equal efficiency.
            _,device,handle,state=max(mirrors,key=lambda item:item[0])
            assert (device,handle) not in selected or selected[device,handle]==state
            selected[device,handle]=state
            b.u32(); b.u32(); b.done()
        elif code == 47:
            device=c.take(16); assert c.u32() == 4 and c.u32() == 32768 and c.u32() == 0
            assert r.u32() == 4
            b = XDR(r.opaque()); assert b.u32() == 1
            assert b.opaque()==b'tcp'
            address,p1,p2=b.opaque().decode('ascii').rsplit('.',2)
            assert address in servers and int(p1)*256+int(p2)==2049
            assert device not in devices or devices[device]==address
            devices[device]=address
            assert b.u32() == 2
            for version in (2, 1):
                assert b.u32() == 4 and b.u32() == version
                assert b.u32() > 0 and b.u32() > 0 and b.u32() == 1
            b.done(); assert r.u32() == 0
        elif code == 51:
            assert tuple(c.u32() for _ in range(4)) == (0, 4, 3, 1)
            assert c.u64() == 0 and c.u64() == 2**64-1
            c.take(16); assert c.opaque() == bytes(8)
            if r.u32():
                r.take(16)
        elif code == 25:
            state, offset, count = c.take(16), c.u64(), c.u32()
            eof, data = r.u32(), r.opaque()
            assert count == len(data) and count > 0 and eof in (0, 1)
            reads[flow].append((offset, data, (server,fh), state))
        c.done(); r.done()
    for (device,fh),state in selected.items():
        if device in devices:handles[devices[device],fh]=state
    assert minors == {1, 2}
    assert counts == {key:value*runs for key,value in {'mds_50':26,'mds_47':26,'mds_51':26,'ds_25':598}.items()}, counts
    complete = partial = 0
    for flow, chunks in reads.items():
        chunks.sort()
        offset, payload = 0, bytearray()
        for pos, data, fh, state in chunks:
            assert pos == offset and handles[fh] == state, 'range or global stateid mismatch'
            payload.extend(data); offset += len(data)
        if len(payload) == 1048593:
            assert hashlib.sha256(payload).hexdigest() == expected_hash
            complete += 1
        else:
            assert len(payload) == 32768, len(payload)
            partial += 1
    assert (complete, partial) == (18*runs, 4*runs)
    return dict(passed=True, counts=dict(counts), complete_native_payloads=complete,
                cancelled_partial_payloads=partial, sha256=expected_hash,
                mds_minors=sorted(minors), ds_minor=2, mirrors=len(servers), profile_runs=runs,
                capture_sha256=hashlib.sha256(capture.read_bytes()).hexdigest())


if __name__ == '__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('capture',type=pathlib.Path); parser.add_argument('sha256'); parser.add_argument('output',type=pathlib.Path)
    parser.add_argument('--servers',nargs='+',default=['192.168.116.131']); parser.add_argument('--runs',type=int,default=1)
    args=parser.parse_args()
    result=audit(args.capture,args.sha256,args.servers,args.runs)
    args.output.write_text(json.dumps(result,indent=2)+'\n')
    print(json.dumps(result, indent=2))
