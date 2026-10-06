"""Negative controls for the independent native Flex evidence decoder."""
import pathlib
import struct
import unittest
from unittest.mock import patch

import audit_flex


def words(*values):
    return b''.join(struct.pack('!I', n) for n in values)


def opaque(value):
    return words(len(value))+value+bytes(-len(value)%4)


class FlexAuditTests(unittest.TestCase):
    def test_opaque_bounds(self):
        for value in (b'', b'a', bytes(32768), bytes(2**20)):
            d = audit_flex.XDR(opaque(value))
            self.assertEqual(d.opaque(), value)
            d.done()
        for data in (words(2**20+1), words(1)+b'a', words(8)+b'abcd'):
            with self.assertRaises(AssertionError):
                audit_flex.XDR(data).opaque()

    def test_no_capture_is_not_evidence(self):
        with patch.object(audit_flex, 'messages', return_value=[]):
            with self.assertRaises(AssertionError):
                audit_flex.audit(pathlib.Path('unused'), '0'*64)

    def test_protocol_refusals(self):
        credential = words(0)+opaque(b'nfs-viewer')+words(25001,25000,0)
        for mode in ('mds-read', 'wrong-ds-version', 'failed-reply', 'incomplete', 'changed-replay'):
            with self.subTest(mode=mode):
                server = 'c0a87482' if mode == 'mds-read' else 'c0a87483'
                minor = 1 if mode == 'wrong-ds-version' else 2
                call = words(17,0,2,100003,4,1,1)+opaque(credential)+words(0,0)
                call += opaque(b'')+words(minor,1,25)+bytes(16)+struct.pack('!Q',0)+words(1)
                reply = words(17,1,0,0,0,0,5 if mode == 'failed-reply' else 0)+opaque(b'')+words(1,25,0,1)+opaque(b'a')
                key = ('c0a87401',12345,server,2049)
                packets = [('tcp',key,call)]
                if mode == 'changed-replay':
                    packets.append(('tcp',key,call+b'x'))
                if mode != 'incomplete':
                    packets.append(('tcp',(server,2049,'c0a87401',12345),reply))
                with patch.object(audit_flex,'messages',return_value=packets):
                    with self.assertRaises(AssertionError):
                        audit_flex.audit(pathlib.Path('unused'),'0'*64)


if __name__ == '__main__':
    unittest.main()
