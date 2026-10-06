"""Check blocking NLM identities, callbacks and cancellation independently."""
import collections
import hashlib
import json
import pathlib
import struct
import sys

from audit import XDR, messages


def audit_callbacks(path, native):
    pairs = collections.defaultdict(dict)
    for transport, key, data in messages(path):
        xid, direction = struct.unpack("!II", data[:8])
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[(transport, flow, xid)]
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    acquisitions, callbacks, acknowledgements = {}, {}, {}
    releases, cancellations = [], []
    counts = collections.Counter()
    for (transport, _, _), pair in pairs.items():
        if 0 not in pair:
            continue
        call = XDR(pair[0])
        call.take(8)
        assert call.u32() == 2
        program, version, procedure = call.u32(), call.u32(), call.u32()
        call.u32(); call.opaque(); call.u32(); call.opaque()
        if program != 100021 or procedure not in (2, 3, 4, 10, 15):
            continue
        counts[f"{version}/{procedure}/{transport}"] += 1
        assert version in (1, 4)
        cookie = call.opaque()
        if procedure == 15:
            status = call.u32(); call.done()
            acknowledgements[(version, cookie)] = status
            continue
        exclusive = None
        blocking = False
        if procedure in (2, 3):
            block = call.u32()
            assert block in (0, 1)
            blocking = bool(block)
            if procedure == 3:
                assert blocking, "nonblocking CANCEL"
        if procedure in (2, 3, 10):
            exclusive = call.u32()
            assert exclusive in (0, 1)
        caller, handle, owner, svid = call.opaque(), call.opaque(), call.opaque(), call.u32()
        offset, length = (call.u32(), call.u32()) if version == 1 else (call.u64(), call.u64())
        identity = (version, caller, handle, owner, svid, offset, length)
        if procedure == 2:
            assert call.u32() == 0, "unexpected reclaim"
            assert call.u32() % 2 == 1
        call.done()
        status = None
        if procedure in (2, 3, 4) and 1 in pair:
            reply = XDR(pair[1]); reply.take(8)
            assert reply.u32() == 0
            reply.u32(); reply.opaque()
            assert reply.u32() == 0 and reply.opaque() == cookie
            status = reply.u32(); reply.done()
        if procedure == 2:
            assert identity not in acquisitions, "repeated LOCK for one owner"
            acquisitions[identity] = (exclusive, status, blocking)
        elif procedure == 3:
            cancellations.append((identity, exclusive, status))
        elif procedure == 4:
            releases.append((identity, status))
        else:
            callbacks[(version, cookie)] = (identity, exclusive)
    successful = []
    for key, status in acknowledgements.items():
        assert key in callbacks, "reply without captured grant"
        identity, exclusive = callbacks[key]
        assert identity in acquisitions
        assert acquisitions[identity] == (exclusive, 3, True), "grant lacks acknowledged blocking LOCK"
        if status == 0:
            assert (identity, 0) in releases, "accepted grant not released"
            successful.append(identity)
    clean_cancels = []
    for identity, exclusive, status in cancellations:
        assert identity in acquisitions and acquisitions[identity][0] == exclusive
        if status in (0, 1) and (identity, 0) in releases:
            clean_cancels.append(identity)
    # Match the final matrix to independently obtained FreeBSD getfh handles,
    # excluding exploratory Docker/VM runs retained in this same capture.
    profiles = json.loads(native.read_text())
    assert len(profiles) == 24
    final_grants = final_cancels = 0
    for profile in profiles:
        handle = bytes.fromhex(profile["fh"])
        matches = [identity for identity in acquisitions
                   if identity[2] == handle or identity[0] == 1 and identity[2] == handle + b"\x00" * 4]
        assert len(matches) == 1, (profile["profile"], "not exactly one LOCK")
        identity = matches[0]
        assert acquisitions[identity][1:] == (3, True), (profile["profile"], "did not queue")
        if profile["profile"].endswith("-grant"):
            assert identity in successful, (profile["profile"], "no callback grant/release")
            final_grants += 1
        else:
            assert identity in clean_cancels, (profile["profile"], "no confirmed cancellation/release")
            final_cancels += 1
    assert final_grants == 16 and final_cancels == 8
    assert {x[0] for x in successful} == {1, 4}
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "counts": dict(counts), "single_request_owners": len(acquisitions),
            "granted_and_released": len(set(successful)),
            "cancelled_and_released": len(set(clean_cancels)),
            "final_callback_profiles": final_grants, "final_cancel_profiles": final_cancels,
            "unacknowledged_callbacks": len(set(callbacks) - set(acknowledgements))}


if __name__ == "__main__":
    print(json.dumps(audit_callbacks(pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])), indent=2))
