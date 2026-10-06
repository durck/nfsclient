"""Capture reconstruction regressions (no live service required)."""
import pathlib
import struct
import tempfile
import unittest

from audit import messages


def packet(sequence, flags, body=b""):
    tcp = struct.pack("!HHIIBBHHH", 40000, 20021, sequence, 0, 0x50, flags, 65535, 0, 0) + body
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(tcp), 0, 0, 64, 6, 0, b"\x7f\0\0\1", b"\x7f\0\0\2") + tcp
    frame = b"\0" * 12 + b"\x08\0" + ip
    return struct.pack("<IIII", 0, 0, len(frame), len(frame)) + frame


class CaptureTests(unittest.TestCase):
    def test_reused_tcp_tuple_is_not_one_stream(self):
        capture = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 262144, 1)
        for seq, body in ((100, b"first"), (9000, b"second")):
            record = struct.pack("!I", 0x80000000 | len(body)) + body
            capture += packet(seq, 2) + packet(seq + 1, 24, record)
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "reuse.pcap"
            path.write_bytes(capture)
            self.assertEqual([x[2] for x in messages(path)], [b"first", b"second"])


class CaptureRecords(unittest.TestCase):
    def capture(self, body):
        data = bytearray(struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 1))
        for seq, flags, payload in [(100, 2, b""), (101, 0x18, body),
                                    (101 + len(body), 0x11, b""),
                                    (101 + len(body), 0x10, b"\x00")]:
            tcp = struct.pack("!HHIIBBHHH", 12345, 20021, seq, 0, 0x50, flags, 4096, 0, 0) + payload
            ip = bytearray(20); ip[0] = 0x45; ip[9] = 6
            struct.pack_into("!H", ip, 2, len(ip) + len(tcp))
            packet = bytes(12) + b"\x08\x00" + ip + tcp
            data.extend(struct.pack("<IIII", 1, 0, len(packet), len(packet)) + packet)
        return data

    def test_fin_probe_does_not_extend_rpc(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "capture.pcap"
            path.write_bytes(self.capture(struct.pack("!I", 0x80000004) + b"test"))
            self.assertEqual([m[2] for m in messages(path)], [b"test"])

    def test_truncated_rpc_still_fails(self):
        with tempfile.TemporaryDirectory() as root:
            path = pathlib.Path(root) / "capture.pcap"
            path.write_bytes(self.capture(struct.pack("!I", 0x80000008) + b"test"))
            with self.assertRaisesRegex(AssertionError, "truncated RPC"):
                list(messages(path))


if __name__ == "__main__":
    unittest.main()
