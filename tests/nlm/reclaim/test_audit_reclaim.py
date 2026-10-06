import collections
import hashlib
import json
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

from audit_reclaim import audit


def words(*values):
    return struct.pack("!" + "I" * len(values), *values)


def opaque(value):
    return words(len(value)) + value + bytes(-len(value) % 4)


class ReclaimAuditTests(unittest.TestCase):
    def run_fixture(self, failure=None):
        records = collections.defaultdict(list)
        names = []
        xid = owner_id = profile = 0
        for platform, caller in [("windows", b"127.0.0.2"), ("linux", b"127.0.0.3")]:
            for version in (1, 4):
                for mode in ("ranges", "resume", "late"):
                    profile += 1
                    names.append(f"/data/reclaim-{platform}-{2 if version == 1 else 3}-{mode}")
                    for lock in range(2 if mode == "ranges" else 1):
                        owner_id += 1
                        offset, length = (lock * 8192, 4096) if mode == "ranges" else (0, 0)
                        owner = bytes([owner_id]) * 16
                        span = words(offset, length) if version == 1 else struct.pack("!QQ", offset, length)
                        auth = words(0) + opaque(b"nfs-viewer") + words(20001, 20001, 0)
                        for event in range(3):
                            xid += 1
                            boot = profile if event == 0 else profile + 1
                            proc = 4 if event == 2 else 2
                            cookie = bytes([xid]) * 16
                            actual_owner = bytes([99]) * 16 if failure == "changed-owner" and xid == 2 else owner
                            identity = opaque(caller) + opaque(bytes([profile]) * 32) + opaque(actual_owner) + words(owner_id) + span
                            call = words(xid, 0, 2, 100021, version, proc, 1) + opaque(auth) + words(0, 0) + opaque(cookie)
                            if proc == 2:
                                reclaim = int(event == 1)
                                if failure == "replacement" and xid == 2:
                                    reclaim = 0
                                call += words(0, lock) + identity + words(reclaim, 1)
                            else:
                                call += identity
                            status = 4 if mode == "late" and event == 1 else 0
                            if failure == "late-accepted" and status == 4:
                                status = 0
                            reply = words(xid, 1, 0, 0, 0, 0) + opaque(cookie) + words(status)
                            key = ("client", 30000 + owner_id, "server", 19521)
                            records[boot].append(("tcp", key, call))
                            if failure != "lost-reply" or xid != 2:
                                records[boot].append(("tcp", key, reply))
        with tempfile.TemporaryDirectory() as tmp:
            root = pathlib.Path(tmp)
            for i in range(1, 14):
                (root / f"network-{i}.pcap").touch()
            (root / "boots.log").write_text("\n".join(map(str, range(13))))
            epochs = list(range(3, 29, 2))
            if failure == "epoch":
                epochs[3] += 2
            (root / "statd-states.log").write_text("\n".join(map(str, epochs)))
            (root / "console-13.log").write_text("Power down")
            digest = hashlib.sha256(b"NLM restart preserves owner and data.\n" * 16384).hexdigest()
            lines = [f"{digest}  {name}" for name in names]
            if failure == "hash":
                lines[0] = "0" * 64 + "  " + names[0]
            if failure == "duplicate":
                lines.append(lines[0])
            (root / "native-sha256.txt").write_text("\n".join(lines))
            observations = []
            for name in names:
                name = pathlib.PurePosixPath(name).name
                mode = name.rsplit("-", 1)[1]
                for lock in range(1, 3 if mode == "ranges" else 2):
                    offset, length = ((lock - 1) * 8192, 4096) if mode == "ranges" else (0, 0)
                    phases = {"initial": True, "late-free": False} if mode == "late" else {"initial": True, "reclaimed": True, "released": False}
                    for phase, conflict in phases.items():
                        observations.append(dict(token=f"{name}-{phase}-{lock}", name=name, offset=offset, length=length, conflict=conflict))
            if failure == "posix":
                observations[0]["conflict"] = False
            (root / "posix-probes.jsonl").write_text("\n".join(json.dumps(item) for item in observations))
            with patch("audit_reclaim.messages", side_effect=lambda path: records[int(path.stem.split("-")[1])]):
                return audit(root)

    def test_complete_recovery(self):
        self.assertEqual(self.run_fixture()["confirmed_reclaims"], 12)

    def test_invalid_evidence(self):
        for failure in ("changed-owner", "replacement", "late-accepted", "lost-reply", "epoch", "hash", "duplicate", "posix"):
            with self.subTest(failure=failure), self.assertRaises(AssertionError):
                self.run_fixture(failure)


if __name__ == "__main__":
    unittest.main()
