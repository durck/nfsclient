import pathlib
import struct
import unittest
from unittest.mock import patch

import audit_offload


def words(*args): return b''.join(struct.pack('!I', n) for n in args)
def wide(n): return struct.pack('!Q', n)
def opaque(b): return words(len(b)) + b + b'\0' * (-len(b) % 4)
def request(xid, prog): return words(xid, 0, 2, prog, 4 if prog == 100003 else 1, 1, 0, 0, 0, 0)
def response(xid): return words(xid, 1, 0, 0, 0, 0)


def fixture(wrong_file=False, missing=False, excess=False, synchronous=False):
    flow = ('client', 2000, 'server', 2049)
    reverse = ('server', 2049, 'client', 2000)
    records = []
    sid = b'S' * 16
    for i in (1, 2):
        state = bytes([i]) * 16
        call = request(i, 100003) + opaque(b'') + words(2, 5, 53) + sid + words(i, 0, 0, 1)
        call += words(22) + opaque(b'source') + words(32, 22) + opaque(b'destination')
        call += words(60) + b'L' * 32 + wide(0) + wide(0) + wide(6) + words(1, 0, 0)
        reply = response(i) + words(0) + opaque(b'') + words(5, 53, 0) + sid + words(i, 0, 0, 0, 0)
        reply += words(22, 0, 32, 0, 22, 0, 60, 0)
        reply += words(0 if synchronous else 1) + (b'' if synchronous else state) + wide(0) + words(0) + b'verifier' + words(1, int(synchronous))
        records += [('tcp', flow, call), ('tcp', reverse, reply)]
        cb = request(10 + i, 0x40000001) + opaque(b'') + words(2, 0, 2, 11) + sid + words(i, 0, 0, 0, 0)
        cb += words(15) + opaque(b'wrong' if wrong_file else b'destination') + state + words(0, 0) + wide(7 if excess else 6) + words(2) + b'verifier'
        ack = response(10 + i) + words(0) + opaque(b'') + words(2, 11, 0) + sid + words(i, 0, 0, 0) + words(15, 0)
        if not missing:
            records += [('tcp', reverse, cb), ('tcp', flow, ack)]
    call = request(3, 100003) + opaque(b'') + words(2, 3, 53) + sid + words(3, 0, 0, 1)
    call += words(22) + opaque(b'destination') + words(70)
    records += [('tcp', flow, call), ('tcp', reverse, response(3) + words(10004))]
    return records


class AuditTests(unittest.TestCase):
    def run_audit(self, **kwargs):
        with patch.object(audit_offload, 'messages', return_value=fixture(**kwargs)):
            return audit_offload.audit(pathlib.Path('unused'), 2)

    def test_valid_pairs(self):
        self.assertEqual(self.run_audit()['matched_completed_callbacks'], 2)

    def test_mismatched_completion(self):
        for case in ('wrong_file', 'missing', 'excess', 'synchronous'):
            with self.subTest(case=case), self.assertRaises(AssertionError):
                self.run_audit(**{case: True})


if __name__ == '__main__': unittest.main()
