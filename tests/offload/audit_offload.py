"""Independently match asynchronous COPY and CB_OFFLOAD in an Ethernet capture."""
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "nlm/freebsd"))
from audit import XDR, messages  # shared bounded Ethernet/TCP/XDR decoder


def rpc_body(data, reply=False):
    d = XDR(data)
    d.take(8)
    if reply:
        assert d.u32() == 0
        d.u32(); d.opaque()
        assert d.u32() == 0
        return d
    assert d.u32() == 2
    program, version, procedure = d.u32(), d.u32(), d.u32()
    d.u32(); d.opaque(); d.u32(); d.opaque()
    return program, version, procedure, d


def audit(path, expected=12):
    pairs = {}
    for transport, key, data in messages(path):
        if transport != "tcp":
            continue
        xid, direction = struct.unpack("!II", data[:8])
        origin = key if direction == 0 else (key[2], key[3], key[0], key[1])
        pair = pairs.setdefault((origin, xid), {})
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    copies, callbacks, refusals = {}, [], 0
    for (origin, xid), pair in pairs.items():
        if 0 not in pair:
            continue
        program, version, procedure, d = rpc_body(pair[0])
        if procedure != 1 or (program, version) not in ((100003, 4), (0x40000001, 1)):
            continue
        d.opaque(); minor = d.u32()
        if program == 0x40000001:
            d.u32()
            n, op = d.u32(), d.u32()
            assert minor == 2 and op == 11
            d.take(16); sequence = d.u32(); d.take(12)
            refs = d.u32()
            for _ in range(refs):
                d.take(16)
                for _ in range(d.u32()): d.take(8)
            if n != 2 or d.u32() != 15:
                continue
            fh, state, status = d.opaque(), d.take(16), d.u32()
            assert status == 0 and d.u32() == 0
            count, stable, verifier = d.u64(), d.u32(), d.take(8)
            d.done()
            assert 1 in pair, "unacknowledged completion callback"
            r = rpc_body(pair[1], True)
            status = r.u32(); r.opaque(); n = r.u32()
            assert r.u32() == 11
            seq_status = r.u32()
            if seq_status == 0: r.take(32)
            if n == 2:
                assert r.u32() == 15 and r.u32() == status
            r.done()
            if status == 0:
                callbacks.append((origin, fh, state, count, stable, verifier, sequence))
            else:
                assert status in (10008, 10068), status
            continue
        n, op = d.u32(), d.u32()
        if minor != 2 or op != 53 or n not in (3, 5):
            continue
        d.take(32)
        if d.u32() != 22: continue
        source = d.opaque()
        operation = d.u32()
        if n == 3 and operation == 70:
            assert 1 in pair
            r = rpc_body(pair[1], True)
            assert r.u32() == 10004
            refusals += 1
            continue
        if n != 5 or operation != 32: continue
        assert d.u32() == 22
        destination = d.opaque()
        if d.u32() != 60: continue
        d.take(32)
        source_offset, destination_offset, length = d.u64(), d.u64(), d.u64()
        assert d.u32() == 1 and d.u32() == 0 and d.u32() == 0
        d.done()
        assert 1 in pair
        r = rpc_body(pair[1], True)
        assert r.u32() == 0
        r.opaque(); assert r.u32() == 5 and r.u32() == 53 and r.u32() == 0
        r.take(36)
        for code in (22, 32, 22, 60): assert r.u32() == code and r.u32() == 0
        assert r.u32() == 1, "COPY did not return an asynchronous ID"
        state = r.take(16); initial_count = r.u64(); stable = r.u32(); r.take(8)
        assert initial_count <= length and stable <= 2 and r.u32() == 1 and r.u32() == 0
        r.done()
        reverse = (origin[2], origin[3], origin[0], origin[1])
        key = (reverse, destination, state)
        assert key not in copies, "reused asynchronous COPY identity"
        copies[key] = length
    completed = set()
    for origin, fh, state, count, stable, verifier, sequence in callbacks:
        key = (origin, fh, state)
        assert key in copies and count == copies[key] and stable == 2
        completed.add(key)
    assert len(copies) == len(completed) == expected, (len(copies), len(completed))
    assert refusals == expected // 2, refusals
    return {"passed": True, "asynchronous_copies": len(copies), "matched_completed_callbacks": len(completed),
            "write_same_NOTSUPP": refusals, "file_sync_callbacks": True}


if __name__ == "__main__":
    print(json.dumps(audit(pathlib.Path(sys.argv[1]), int(sys.argv[2]) if len(sys.argv) > 2 else 12), indent=2))
