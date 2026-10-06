"""Verify queued owners are never replayed or unlocked after a service restart."""
import collections
import json
import pathlib
import re
import struct
import sys

from audit import XDR, messages


def audit_wait_restart(capture, event_path):
    pairs = collections.defaultdict(dict)
    for transport, key, data in messages(capture):
        xid, direction = struct.unpack("!II", data[:8])
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[(transport, flow, xid)]
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    operations = collections.defaultdict(list)
    blocked = {}
    for pair in pairs.values():
        if 0 not in pair:
            continue
        q = XDR(pair[0]); q.take(12)
        program, version, procedure = q.u32(), q.u32(), q.u32()
        if program != 100021 or procedure not in (2, 3, 4):
            continue
        q.u32(); q.opaque(); q.u32(); q.opaque()
        cookie = q.opaque()
        block = exclusive = None
        if procedure in (2, 3):
            block, exclusive = q.u32(), q.u32()
        caller, handle, owner, svid = q.opaque(), q.opaque(), q.opaque(), q.u32()
        offset, length = (q.u32(), q.u32()) if version == 1 else (q.u64(), q.u64())
        if procedure == 2:
            assert q.u32() == 0, "automatic reclaim"
            q.u32()
        q.done()
        identity = (version, caller, handle, owner, svid, offset, length)
        operations[identity].append(procedure)
        if procedure == 2 and 1 in pair:
            r = XDR(pair[1]); r.take(8)
            assert r.u32() == 0
            r.u32(); r.opaque()
            assert r.u32() == 0 and r.opaque() == cookie
            status = r.u32(); r.done()
            if block == 1 and status == 3:
                assert exclusive == 1 and offset == 8 and length == 8
                blocked[cookie.hex()] = identity
    events = json.loads(event_path.read_text())
    expected = {f"restart-{os}-{version}-{service}" for os in ("windows", "linux")
                for version in (2, 3) for service in ("statd", "lockd")}
    assert {e["profile"] for e in events} == expected and len(events) == 8
    for event in events:
        identity = blocked[event["queued_cookie"]]
        assert operations[identity] == [2], (event["profile"], "LOCK/CANCEL/UNLOCK replay")
        match = re.fullmatch(r"old=(.*?) new=(.*)", event["service_restart"], re.S)
        assert match and not (set(match[1].split()) & set(match[2].split()))
        assert identity[0] == (1 if "-2-" in event["profile"] else 4)
    return {"passed": True, "queued_restart_profiles": len(events),
            "one_LOCK_per_pending_owner": True, "no_CANCEL_or_UNLOCK_replay": True,
            "changed_service_pids": True}


if __name__ == "__main__":
    print(json.dumps(audit_wait_restart(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))
