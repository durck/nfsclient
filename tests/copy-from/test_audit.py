import pathlib
import struct
import tempfile
import unittest

from audit_copy import XDR, locations, native, result


def u32(*values):
    return struct.pack('!'+len(values)*'I', *values)


def opaque(value):
    return u32(len(value))+value+bytes(-len(value)%4)


class AuditTests(unittest.TestCase):
    def test_literal_locations(self):
        data=u32(1,3)+opaque(b'tcp')+opaque(b'192.0.2.1.8.1')
        self.assertEqual(locations(XDR(data)),[(b'tcp',b'192.0.2.1.8.1')])
        for bad in [u32(0),u32(65),u32(1,1)+opaque(b'host')]:
            with self.assertRaises(AssertionError): locations(XDR(bad))
        for end in range(len(data)):
            with self.assertRaises(AssertionError): locations(XDR(data[:end]))

    def test_confirmed_operation_result(self):
        header=u32(1,1,0,0,0,0)
        body=u32(0)+opaque(b'')+u32(3,53,0)+bytes(36)+u32(22,0,66,0)
        result({1:header+body},[22,66]).done()
        with self.assertRaises(AssertionError): result({},[22,66])
        with self.assertRaises(AssertionError): result({1:header+body},[22,61])
        with self.assertRaises(AssertionError): result({1:header+body[:-4]+u32(5)},[22,66])

    def test_native_missing_and_changed_files(self):
        hashes={'src':'ae153fe22d3c029ebc35a66108da1e4bf472be97dcf24f27e0b18beec72a02ec',
                'dst':'29d0be1fecdf8e1a96617fd88f94de19b781d58ce49a1270c9723f25683f8698'}
        with tempfile.TemporaryDirectory() as tmp:
            root=pathlib.Path(tmp)
            for role,kind in [('source','src'),('destination','dst')]:
                (root/role).mkdir()
                lines=[f'{hashes[kind]}  /data/copyfrom-{os}-{mode}-{kind}\n' for os in ('windows','linux') for mode in ('session','locked','cli')]
                (root/role/'native-sha256.txt').write_text(''.join(lines))
            self.assertEqual(native(root)['native_files'],12)
            path=root/'destination/native-sha256.txt'
            good=path.read_text()
            for bad in [good.replace(hashes['dst'],'0'*64,1), '\n'.join(good.splitlines()[1:]), good+good.splitlines()[0]+'\n']:
                path.write_text(bad)
                with self.assertRaises(AssertionError): native(root)


if __name__=='__main__': unittest.main()
