import json
import os
import socket
import unittest
from unittest.mock import patch

from omarchy_wireguard.protocol import ProtocolError, authorized, peer_credentials, read_request


class ProtocolTests(unittest.TestCase):
    def test_peer_credentials_and_authorization(self):
        left, right = socket.socketpair(socket.AF_UNIX)
        try:
            _pid, uid, _gid = peer_credentials(left)
            self.assertEqual(uid, os.getuid())
            self.assertTrue(authorized(uid, uid))
            self.assertTrue(authorized(0, 1234))
            self.assertFalse(authorized(1235, 1234))
        finally:
            left.close()
            right.close()

    def test_reads_one_strict_request(self):
        left, right = socket.socketpair()
        try:
            right.sendall(json.dumps({"op": "status", "args": {}}).encode() + b"\n")
            self.assertEqual(read_request(left)["op"], "status")
        finally:
            left.close()
            right.close()

    def test_rejects_unknown_fields_and_multiple_requests(self):
        for payload in (b'{"op":"status","extra":1}\n', b'{"op":"status"}\n{}\n'):
            left, right = socket.socketpair()
            try:
                right.sendall(payload)
                with self.assertRaises(ProtocolError):
                    read_request(left)
            finally:
                left.close()
                right.close()

    def test_size_limit(self):
        left, right = socket.socketpair()
        try:
            with patch("omarchy_wireguard.protocol.MAX_REQUEST", 20):
                right.sendall(b'{"op":"status","padding":"x"}\n')
                with self.assertRaisesRegex(ProtocolError, "too large"):
                    read_request(left)
        finally:
            left.close()
            right.close()


if __name__ == "__main__":
    unittest.main()
