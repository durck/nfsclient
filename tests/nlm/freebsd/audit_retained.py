"""Independently inspect retained NLM/NSM RPCs in the disposable lab capture."""
import collections
import hashlib
import json
import pathlib
import struct
import sys

from audit import XDR, messages


def audit_retained(path):
    pairs = collections.defaultdict(dict)
    for transport, key, data in messages(path):
        xid, direction = struct.unpack("!II", data[:8])
        assert direction in (0, 1)
        flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
        pair = pairs[(transport, flow, xid)]
        assert direction not in pair or pair[direction] == data
        pair[direction] = data
    counts, epochs, owners = collections.Counter(), set(), set()
    acquired, released, notifications = {}, [], []
    for (transport, _, _), pair in pairs.items():
        if 0 not in pair:
            continue
        call = XDR(pair[0])
        call.take(8)
        assert call.u32() == 2
        program, version, procedure = call.u32(), call.u32(), call.u32()
        flavor, credentials = call.u32(), call.opaque()
        assert call.u32() == 0 and call.opaque() == b""
        label = f"{program}/{version}/{procedure}/{transport}"
        counts[label + "/requests"] += 1
        reply = None
        if 1 in pair:
            reply = XDR(pair[1])
            reply.take(8)
            assert reply.u32() == 0
            reply.u32()
            reply.opaque()
            assert reply.u32() == 0
            counts[label + "/replies"] += 1
        if program == 100024 and procedure == 1 and reply:
            assert reply.u32() == 0
            epoch = reply.u32()
            assert 0 < epoch <= 0x7fffffff and epoch % 2 == 1
            epochs.add(epoch)
            reply.done()
        if program == 100024 and procedure == 6:
            name, epoch = call.opaque(), call.u32()
            call.done()
            assert name and epoch > 0
            if reply:
                reply.done()
                epochs.add(epoch)
                notifications.append({"transport": transport, "epoch": epoch})
        if program != 100021 or procedure not in (2, 4):
            continue
        assert transport == "tcp" and version in (1, 4) and flavor == 1
        cred = XDR(credentials)
        cred.u32()
        assert cred.opaque() == b"nfs-viewer"
        assert cred.u32() == 20001 and cred.u32() == 20001
        for _ in range(cred.u32()):
            cred.u32()
        cred.done()
        cookie = call.opaque()
        assert len(cookie) == 16
        if procedure == 2:
            assert call.u32() == 0, "blocking LOCK unexpectedly used"
            assert call.u32() in (0, 1)
        assert call.opaque(), "missing caller identity"
        fh, owner, svid = call.opaque(), call.opaque(), call.u32()
        assert len(fh) == 32 if version == 1 else 0 < len(fh) <= 64
        assert len(owner) == 16 and 0 < svid <= 0x7fffffff
        offset = call.u32() if version == 1 else call.u64()
        length = call.u32() if version == 1 else call.u64()
        assert (offset, length) in ((0, 0), (0, 4), (4, 4))
        if procedure == 2:
            assert owner not in owners, "owner reused across acquisitions"
            owners.add(owner)
            assert call.u32() == 0, "unexpected reclaim"
            state = call.u32()
            assert 0 < state <= 0x7fffffff and state % 2 == 1
            acquired[owner] = (version, fh, svid, offset, length)
        else:
            released.append((owner, (version, fh, svid, offset, length)))
        call.done()
        assert reply is not None, "unconfirmed captured mutation"
        assert reply.opaque() == cookie and reply.u32() == 0
        reply.done()
    assert owners and len(epochs) >= 2
    for owner, identity in released:
        assert acquired.get(owner) == identity, "UNLOCK differs from captured acquisition"
    return {"sha256": hashlib.sha256(path.read_bytes()).hexdigest(),
            "rpc_counts": dict(sorted(counts.items())),
            "unique_acquisition_owners": len(owners),
            "observed_nsm_epochs": sorted(epochs),
            "exact_owner_releases": len(released),
            "confirmed_notifications": notifications,
            "notification_delivery_claim": bool(notifications)}


if __name__ == "__main__":
    print(json.dumps(audit_retained(pathlib.Path(sys.argv[1])), indent=2))
