import array
import json
import os
import socket
import tempfile
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
            request, source_fd = read_request(left)
            self.assertEqual(request["op"], "status")
            self.assertIsNone(source_fd)
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

    def test_import_request_receives_one_cloexec_descriptor(self):
        left, right = socket.socketpair()
        received = None
        with tempfile.TemporaryFile() as source:
            source.write(b"profile bytes")
            source.flush()
            payload = json.dumps({
                "op": "import", "args": {"source": "fd", "name": "home.conf"},
            }).encode() + b"\n"
            right.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array("i", [source.fileno()]))])
            try:
                request, received = read_request(left)
                self.assertEqual(request["op"], "import")
                self.assertIsNotNone(received)
                self.assertEqual(os.pread(received, 20, 0), b"profile bytes")
                self.assertFalse(os.get_inheritable(received))
            finally:
                if received is not None:
                    os.close(received)
                left.close()
                right.close()

    def test_descriptors_are_bound_only_to_fd_imports(self):
        requests = (
            {"op": "status", "args": {}},
            {"op": "import", "args": {"name": "home.conf"}},
            {"op": "import", "args": {"source": "fd", "name": "home.conf", "data": "eA=="}},
        )
        for request in requests:
            with self.subTest(request=request):
                left, right = socket.socketpair()
                with tempfile.TemporaryFile() as source:
                    payload = json.dumps(request).encode() + b"\n"
                    right.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                               array.array("i", [source.fileno()]))])
                    try:
                        with self.assertRaises(ProtocolError):
                            read_request(left)
                    finally:
                        left.close()
                        right.close()

    def test_truncated_descriptor_control_data_does_not_leak_fds(self):
        left, right = socket.socketpair()
        sources = [tempfile.TemporaryFile() for _ in range(8)]
        try:
            before = len(os.listdir("/proc/self/fd"))
            payload = json.dumps({
                "op": "import", "args": {"source": "fd", "name": "home.conf"},
            }).encode() + b"\n"
            right.sendmsg([payload], [(socket.SOL_SOCKET, socket.SCM_RIGHTS,
                                       array.array("i", [source.fileno() for source in sources]))])
            with self.assertRaises(ProtocolError):
                read_request(left)
            self.assertEqual(len(os.listdir("/proc/self/fd")), before)
        finally:
            left.close()
            right.close()
            for source in sources:
                source.close()


if __name__ == "__main__":
    unittest.main()
