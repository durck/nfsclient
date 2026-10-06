"""Independently match original/reclaimed NLM owners across kernel reboots."""
import collections
import hashlib
import json
import pathlib
import struct
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1] / "freebsd"))
from audit import XDR, messages


def audit(root):
    owners = collections.defaultdict(list)
    cookies = set()
    for capture in sorted(root.glob("network-*.pcap"), key=lambda p: int(p.stem.split("-")[1])):
        pairs = collections.defaultdict(dict)
        for transport, key, data in messages(capture):
            xid, direction = struct.unpack("!II", data[:8])
            flow = tuple(sorted(((key[0], key[1]), (key[2], key[3]))))
            pair = pairs[transport, flow, xid]
            assert direction not in pair or pair[direction] == data, "changed retransmission"
            pair[direction] = data
        for (transport, _, _), pair in pairs.items():
            if 0 not in pair:
                continue
            call = XDR(pair[0])
            call.take(8)
            assert call.u32() == 2
            program, version, procedure = call.u32(), call.u32(), call.u32()
            if program != 100021 or procedure not in (2, 4):
                continue
            assert transport == "tcp" and version in (1, 4)
            assert call.u32() == 1
            cred = XDR(call.opaque())
            cred.u32()
            assert cred.opaque() == b"nfs-viewer"
            auth = (cred.u32(), cred.u32(), tuple(cred.u32() for _ in range(cred.u32())))
            cred.done()
            assert auth == (20001, 20001, ())
            assert call.u32() == 0 and call.opaque() == b""
            cookie = call.opaque()
            assert len(cookie) == 16 and cookie not in cookies
            cookies.add(cookie)
            exclusive = None
            if procedure == 2:
                assert call.u32() == 0, "queued/replayed acquisition"
                exclusive = call.u32()
                assert exclusive in (0, 1)
            caller, fh, owner, svid = call.opaque(), call.opaque(), call.opaque(), call.u32()
            assert caller in (b"127.0.0.2", b"127.0.0.3")
            assert len(owner) == 16 and svid > 0 and 0 < len(fh) <= 64
            offset = call.u32() if version == 1 else call.u64()
            length = call.u32() if version == 1 else call.u64()
            reclaim, state = (call.u32(), call.u32()) if procedure == 2 else (None, None)
            call.done()
            assert set(pair) == {0, 1}, "unconfirmed mutation"
            reply = XDR(pair[1])
            reply.take(8)
            assert reply.u32() == 0
            reply.u32()
            reply.opaque()
            assert reply.u32() == 0 and reply.opaque() == cookie
            status = reply.u32()
            reply.done()
            identity = (version, caller, fh, owner, svid, offset, length, auth)
            owners[identity].append((int(capture.stem.split("-")[1]), procedure, reclaim, state, exclusive, status))
    assert len(owners) == 16, f"expected 16 retained owners, got {len(owners)}"
    recovered = late = 0
    for identity, events in owners.items():
        assert len(events) == 3, f"replacement, repeated or missing mutation: {events}"
        initial, reclaimed, unlocked = events
        assert initial[1:4] == (2, 0, 1) and initial[5] == 0
        assert reclaimed[0] == initial[0] + 1
        assert reclaimed[1:4] == (2, 1, 1) and reclaimed[4] == initial[4]
        assert unlocked[0] == reclaimed[0] and unlocked[1] == 4 and unlocked[5] == 0
        if reclaimed[5] == 0:
            recovered += 1
        else:
            assert reclaimed[5] == 4 and identity[5:7] == (0, 0)
            late += 1
    assert (recovered, late) == (12, 4)
    distribution = collections.Counter((identity[0], identity[1]) for identity in owners)
    assert distribution == {(version, caller): 4 for version in (1, 4) for caller in (b"127.0.0.2", b"127.0.0.3")}
    boots = (root / "boots.log").read_text().splitlines()
    epochs = [int(n) for n in (root / "statd-states.log").read_text().split()]
    assert len(boots) == len(set(boots)) == len(epochs) == 13
    assert all(b == a + 2 for a, b in zip(epochs, epochs[1:]))
    expected = hashlib.sha256(b"NLM restart preserves owner and data.\n" * 16384).hexdigest()
    lines = (root / "native-sha256.txt").read_text().splitlines()
    assert len(lines) == 12, "missing or duplicate native file evidence"
    hashes = dict(line.split(maxsplit=1)[::-1] for line in lines)
    names = {f"/data/reclaim-{platform}-{version}-{mode}" for platform in ("windows", "linux") for version in (2, 3) for mode in ("ranges", "resume", "late")}
    assert set(hashes) == names and set(hashes.values()) == {expected}
    observations = [json.loads(line) for line in (root / "posix-probes.jsonl").read_text().splitlines()]
    expected_probes = {}
    for name in names:
        name = pathlib.PurePosixPath(name).name
        mode = name.rsplit("-", 1)[1]
        for lock in range(1, 3 if mode == "ranges" else 2):
            offset, length = ((lock - 1) * 8192, 4096) if mode == "ranges" else (0, 0)
            phases = {"initial": True, "late-free": False} if mode == "late" else {"initial": True, "reclaimed": True, "released": False}
            for phase, conflict in phases.items():
                token = f"{name}-{phase}-{lock}"
                expected_probes[token] = dict(token=token, name=name, offset=offset, length=length, conflict=conflict)
    assert len(observations) == len(expected_probes) == 44
    assert {item["token"]: item for item in observations} == expected_probes
    assert "Power down" in (root / "console-13.log").read_text()
    return dict(passed=True, owners=len(owners), confirmed_reclaims=recovered, late_refusals=late,
                exact_unlocks=16, real_reboots=12, native_file_hashes=12, native_posix_observations=44,
                source_sha256=expected, server_epochs=epochs)


if __name__ == "__main__":
    print(json.dumps(audit(pathlib.Path(sys.argv[1])), indent=2))
