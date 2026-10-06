import unittest
from unittest.mock import MagicMock, patch

import probe_tls


class ProbeTests(unittest.TestCase):
    def test_partial_receive_and_truncation(self):
        connection = MagicMock()
        connection.recv.side_effect = [b'a', b'bc']
        self.assertEqual(probe_tls.receive(connection, 3), b'abc')
        connection.recv.side_effect = [b'a', b'']
        with self.assertRaisesRegex(ValueError, 'truncated'):
            probe_tls.receive(connection, 3)

    def test_invalid_framing_and_acknowledgement(self):
        for wire in (probe_tls.struct.pack('!I', 24),
                     probe_tls.struct.pack('!I', 0x80001000),
                     probe_tls.struct.pack('!I', 0x80000018) + bytes(24)):
            with self.subTest(wire=wire), patch.object(probe_tls.ssl, 'create_default_context') as tls, patch.object(probe_tls.socket, 'create_connection') as connect:
                connection = connect.return_value.__enter__.return_value
                chunks = [wire[:4], wire[4:]]
                connection.recv.side_effect = chunks
                with self.assertRaises(ValueError):
                    probe_tls.probe('192.0.2.1', 2049, 'ca', 'cert', 'key')
                tls.return_value.wrap_socket.assert_not_called()

    def test_alpn_observation_without_nfs_calls(self):
        ack = probe_tls.struct.pack('!5I', 0x4E465354, 1, 0, 0, 8) + b'STARTTLS' + bytes(4)
        for alpn in (None, 'sunrpc', 'http/1.1'):
            with self.subTest(alpn=alpn), patch.object(probe_tls.ssl, 'create_default_context') as tls, patch.object(probe_tls.socket, 'create_connection') as connect:
                connection = connect.return_value.__enter__.return_value
                connection.recv.side_effect = [probe_tls.struct.pack('!I', 0x80000000 | len(ack)), ack]
                secured = tls.return_value.wrap_socket.return_value.__enter__.return_value
                secured.selected_alpn_protocol.return_value = alpn
                secured.getpeercert.return_value = b'certificate'
                result = probe_tls.probe('192.0.2.1', 2049, 'ca', 'cert', 'key')
                self.assertEqual(result['rpc_tls_ready'], alpn == 'sunrpc')
                self.assertEqual(result['nfs_operations_sent'], 0)
                connection.sendall.assert_called_once()
                self.assertEqual(len(connection.sendall.call_args.args[0]), 44)
                secured.sendall.assert_not_called()
                tls.return_value.set_alpn_protocols.assert_called_once_with(['sunrpc'])


if __name__ == '__main__':
    unittest.main()
