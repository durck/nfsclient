import json
import pathlib
import struct
import tempfile
import unittest
from unittest.mock import patch

from audit_wait_restart import audit_wait_restart


def words(*values):
    return b"".join(struct.pack("!I", value) for value in values)


def opaque(value):
    return words(len(value)) + value + b"\0" * (-len(value) % 4)


class RestartAuditTests(unittest.TestCase):
    def fixture(self, replay=False, unchanged_pid=False):
        records, events = [], []
        for os in ("windows", "linux"):
            for nfs_version in (2, 3):
                for service in ("statd", "lockd"):
                    i = len(events) + 1
                    version = 1 if nfs_version == 2 else 4
                    cookie = bytes([i])
                    identity = opaque(b"client") + opaque(b"file") + opaque(bytes([i])) + words(i)
                    identity += words(8, 8) if version == 1 else words(0, 8, 0, 8)
                    call = words(i, 0, 2, 100021, version, 2, 0, 0, 0, 0)
                    call += opaque(cookie) + words(1, 1) + identity + words(0, 1)
                    reply = words(i, 1, 0, 0, 0, 0) + opaque(cookie) + words(3)
                    key = ("client", 30000 + i, "server", 20021)
                    records.extend([("tcp", key, call), ("tcp", key, reply)])
                    if replay and i == 1:
                        unlock = words(100, 0, 2, 100021, version, 4, 0, 0, 0, 0)
                        records.append(("tcp", key, unlock + opaque(b"unlock") + identity))
                    events.append({"profile": f"restart-{os}-{nfs_version}-{service}",
                                   "queued_cookie": cookie.hex(),
                                   "service_restart": "old=1 new=" + ("1" if unchanged_pid else "2")})
        return records, events

    def run_audit(self, **kwargs):
        records, events = self.fixture(**kwargs)
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "events.json"
            path.write_text(json.dumps(events))
            with patch("audit_wait_restart.messages", return_value=records):
                return audit_wait_restart(pathlib.Path("fixture.pcap"), path)

    def test_eight_queued_restarts(self):
        self.assertEqual(self.run_audit()["queued_restart_profiles"], 8)

    def test_unlock_replay_is_rejected(self):
        with self.assertRaisesRegex(AssertionError, "replay"):
            self.run_audit(replay=True)

    def test_unchanged_service_is_rejected(self):
        with self.assertRaises(AssertionError):
            self.run_audit(unchanged_pid=True)


if __name__ == "__main__":
    unittest.main()
