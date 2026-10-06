"""Audit retained locks, restarted reads and native content independently."""
import hashlib
import importlib.util
import json
import pathlib
import re
import struct
import sys

spec = importlib.util.spec_from_file_location('nfs_capture_decoder', pathlib.Path(__file__).resolve().parents[1] / 'nlm/freebsd/audit.py')
decoder = importlib.util.module_from_spec(spec)
spec.loader.exec_module(decoder)
messages, XDR = decoder.messages, decoder.XDR


def rpc_body(data, reply=False):
    d = XDR(data)
    d.take(8)
    if reply:
        assert d.u32() == 0
        d.u32(); d.opaque()
        assert d.u32() == 0
        return d
    assert d.u32() == 2
    program, version, proc = d.u32(), d.u32(), d.u32()
    d.u32(); d.opaque(); d.u32(); d.opaque()
    return program, version, proc, d


def check_reclaim(previous, current):
    assert previous is not None, 'no original confirmed lock'
    assert previous[:3] == current[:3], 'lock type/range changed'
    assert previous[3] != current[3], 'unchanged server client ID'
    assert current[1] == 0 and current[2] == 2**64-1, 'not a whole-file lock'


def audit(root):
    pairs = {}
    for transport, key, data in messages(root / 'network.pcap'):
        if transport != 'tcp':
            continue
        xid, direction = struct.unpack('!II', data[:8])
        origin = key if direction == 0 else (key[2], key[3], key[0], key[1])
        pair = pairs.setdefault((origin, xid), {})
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    locks, reclaimed, opens, reads = {}, {}, [], set()
    for pair in pairs.values():
        if 0 not in pair:
            continue
        program, version, proc, d = rpc_body(pair[0])
        if (program, version, proc) != (100003, 4, 1):
            continue
        d.opaque(); minor, n = d.u32(), d.u32()
        op = d.u32()
        if op == 53:
            d.take(32)
            n -= 1
            if not n:
                continue
            op = d.u32()
        if op != 22 or n < 2:
            continue
        fh = d.opaque()
        op = d.u32()
        if op == 38:
            assert fh not in reclaimed, 'WRITE after successful restart reclaim'
            continue
        if op == 25:
            d.take(16)
            offset = d.u64()
            if fh in reclaimed and offset == 0:
                reads.add(fh)
            continue
        if op not in (12, 18):
            continue
        if op == 18:
            d.take(12); client = d.u64(); owner = d.opaque()
            if d.u32() != 0 or d.u32() != 1:
                continue
            assert d.u32() == 0 and d.u32() == 10
            d.done()
            opens.append((fh, minor, client, owner))
        else:
            kind, reclaim = d.u32(), d.u32()
            offset, length = d.u64(), d.u64()
            assert d.u32() == 1, 'unexpected existing-owner LOCK'
            d.u32(); d.take(16); d.u32()
            client, owner = d.u64(), d.opaque()
            d.done()
        assert 1 in pair, 'missing reclaim/lock reply'
        r = rpc_body(pair[1], True)
        status = r.u32(); r.opaque(); r.u32()
        rop = r.u32()
        if rop == 53:
            assert r.u32() == 0
            r.take(36)
            rop = r.u32()
        assert rop == 22 and r.u32() == 0 and r.u32() == op
        opstatus = r.u32()
        if op == 18:
            assert status == opstatus == 0, 'failed CLAIM_PREVIOUS'
            continue
        if status:
            assert not reclaim, 'failed reclaim LOCK'
            continue
        assert opstatus == 0
        r.take(16); r.done()
        key = (fh, owner)
        if reclaim:
            assert key in locks and fh not in reclaimed
            check_reclaim(locks[key], (kind, offset, length, client))
            reclaimed[fh] = minor
        else:
            locks[key] = (kind, offset, length, client)
    assert len(opens) == len(reclaimed) == len(reads) >= 6
    for minor in (0, 1, 2):
        assert list(reclaimed.values()).count(minor) >= 2
    assert {x[0] for x in opens} == reads == set(reclaimed)
    tokens = (root / 'restarts.log').read_text().splitlines()
    assert len(tokens) == len(set(tokens)) == len(reclaimed)
    selected = set()
    for platform in ('windows','linux'):
        log=(root.parent/(platform+'-native.log')).read_text(encoding='utf-8-sig')
        assert 'FAIL' not in log
        for minor in ('4.0','4.1','4.2'):
            pattern = rf'PROTECTED_RESUME os={platform} version={minor} bytes=557056 attempts=2 restart=true .* unchanged_server_refused source=(\S+)'
            found = re.findall(pattern,log)
            assert len(found)==1
            selected.add(found[0])
    assert len(selected)==6 and selected <= set(tokens)
    digest = hashlib.sha256(b'protected resume\0' * 32768).hexdigest()
    native = {}
    for line in (root / 'native-sha256.txt').read_text().splitlines():
        checksum, name = line.split()
        name = pathlib.PurePosixPath(name).name
        assert name in tokens and checksum == digest
        native[name] = checksum
    assert set(native) == set(tokens)
    return dict(passed=True, final_native_profiles=6, restarts=len(tokens), reclaimed_original_locks=len(reclaimed),
                reread_prefixes=len(reads), no_write_after_reclaim=True,
                final_sources=sorted(selected), exploratory_sources=sorted(set(tokens)-selected),
                native_files=native, capture_sha256=hashlib.sha256((root/'network.pcap').read_bytes()).hexdigest())


if __name__ == '__main__':
    print(json.dumps(audit(pathlib.Path(sys.argv[1])), indent=2))
