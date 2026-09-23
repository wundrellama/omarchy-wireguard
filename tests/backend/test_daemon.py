import json
import os
import socket
import unittest
from unittest.mock import patch

from omarchy_wireguard.controller import RequestFailure
from omarchy_wireguard.daemon import _handle_connection, reconcile_early_firewall
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.protocol import ProtocolError


class Store:
    def __init__(self, state=None, error=None, dns=None):
        self.state = state
        self.error = error
        self.dns = dns or []

    def read(self, name, default):
        if self.error and name == "state.json":
            raise self.error
        if name == "state.json":
            return self.state
        if name == "dns.json":
            return self.dns
        return {}


class System:
    def __init__(self):
        self.removed = 0
        self.applied = 0

    def remove_firewall(self):
        self.removed += 1

    def inspect_firewall_context(self):
        return FirewallContext()

    def apply_firewall(self, context):
        self.applied += 1


class EarlyFirewallTests(unittest.TestCase):
    def test_missing_and_disabled_state_remove_policy(self):
        for state in (None, {"enabled": False, "target": None, "mru": []}):
            system = System()
            reconcile_early_firewall(Store(state), system)
            self.assertEqual((system.removed, system.applied), (1, 0))

    def test_enabled_state_fails_closed(self):
        system = System()
        reconcile_early_firewall(Store({"enabled": True, "target": "Japan/Tokyo", "mru": []}), system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_disabled_state_with_pending_dns_restore_fails_closed(self):
        system = System()
        store = Store({"enabled": False, "target": None, "mru": []},
                      dns=[["eth0", ["~."], True]])
        reconcile_early_firewall(store, system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_missing_state_with_pending_dns_restore_fails_closed(self):
        system = System()
        reconcile_early_firewall(Store(dns=[["eth0", ["~."], True]]), system)
        self.assertEqual((system.removed, system.applied), (0, 1))

    def test_corrupt_or_unsafe_state_fails_closed(self):
        for store in (Store({"enabled": "yes"}), Store(error=RuntimeError("unsafe"))):
            system = System()
            reconcile_early_firewall(store, system)
            self.assertEqual((system.removed, system.applied), (0, 1))

    def test_protocol_rejection_ignores_disconnected_client(self):
        with patch("omarchy_wireguard.daemon.peer_credentials",
                   side_effect=ProtocolError("bad peer")), patch(
                       "omarchy_wireguard.daemon.send_response", side_effect=BrokenPipeError):
            with self.assertLogs("omarchy-wireguard", level="WARNING"):
                _handle_connection(object(), object(), 1000)


class ControllerProbe:
    def __init__(self, error=None):
        self.error = error
        self.calls = []
        self.emergencies = 0
        self.last_error = "original tunnel failure"

    def handle(self, op, args):
        self.calls.append((op, args))
        if self.error is not None:
            raise self.error
        return {"state": "connected"}

    def emergency(self):
        self.emergencies += 1
        self.last_error = "internal safety failure"


class ConnectionTests(unittest.TestCase):
    def test_successful_connect_and_status_survive_lost_response(self):
        for op in ("connect", "status"):
            with self.subTest(op=op):
                # Queue a real request before closing the peer: no timing races.
                server, peer = socket.socketpair()
                with server, peer:
                    peer.sendall(json.dumps({"op": op, "args": {}, "request_id": "r1"}).encode() + b"\n")
                    peer.close()
                    controller = ControllerProbe()
                    with self.assertLogs("omarchy-wireguard", level="WARNING") as logs:
                        _handle_connection(server, controller, os.getuid())
                    self.assertEqual(logs.output,
                                     ["WARNING:omarchy-wireguard:response delivery failed (BrokenPipeError)"])
                    self.assertEqual(controller.calls, [(op, {})])
                    self.assertEqual(controller.emergencies, 0)
                    self.assertEqual(controller.last_error, "original tunnel failure")


    def test_incoming_transport_errors_do_not_isolate_controller(self):
        for boundary in ("peer_credentials", "read_request"):
            with self.subTest(boundary=boundary):
                server, peer = socket.socketpair()
                with server, peer:
                    controller = ControllerProbe()
                    with patch("omarchy_wireguard.daemon." + boundary,
                               side_effect=ConnectionResetError("secret input")):
                        with self.assertLogs("omarchy-wireguard", level="WARNING") as logs:
                            _handle_connection(server, controller, os.getuid())
                    self.assertEqual(controller.calls, [])
                    self.assertEqual(controller.emergencies, 0)
                    self.assertNotIn("secret input", "\n".join(logs.output))

    def test_controller_failure_isolates_once_and_logs_only_type(self):
        for error_type in (RuntimeError, OSError):
            for closed in (False, True):
                with self.subTest(error=error_type, closed=closed):
                    server, peer = socket.socketpair()
                    with server, peer:
                        peer.settimeout(1)
                        peer.sendall(b'{"op":"connect","request_id":"secret request id"}\n')
                        if closed:
                            peer.close()
                        controller = ControllerProbe(error_type("secret private key"))
                        with self.assertLogs("omarchy-wireguard", level="ERROR") as logs:
                            _handle_connection(server, controller, os.getuid())
                        self.assertEqual(controller.calls, [("connect", {})])
                        self.assertEqual(controller.emergencies, 1)
                        self.assertEqual(controller.last_error, "internal safety failure")
                        self.assertIn(error_type.__name__, "\n".join(logs.output))
                        self.assertNotIn("secret", "\n".join(logs.output))
                        for record in logs.records:
                            self.assertIsNone(record.exc_info)
                            self.assertNotIn("request_id", record.__dict__)
                        if not closed:
                            response = json.loads(peer.recv(4096))
                            self.assertEqual(response["error"],
                                             {"code": "internal", "message": "internal failure"})

    def test_rejection_and_incomplete_request_survive_peer_close(self):
        cases = ((b'{"op":"connect"}\n', RequestFailure("rejected"), 1),
                 (b'{"op":"unknown"}\n', None, 0),
                 (b'{"op":', None, 0),
                 (b'', None, 0))
        for payload, error, calls in cases:
            with self.subTest(payload=payload):
                server, peer = socket.socketpair()
                with server, peer:
                    peer.sendall(payload)
                    peer.close()
                    controller = ControllerProbe(error)
                    with self.assertLogs("omarchy-wireguard", level="WARNING"):
                        _handle_connection(server, controller, os.getuid())
                    self.assertEqual(len(controller.calls), calls)
                    self.assertEqual(controller.emergencies, 0)
                    self.assertEqual(controller.last_error, "original tunnel failure")

    def test_rejected_response_keeps_wire_format_without_emergency(self):
        server, peer = socket.socketpair()
        with server, peer:
            peer.settimeout(1)
            peer.sendall(b'{"op":"connect","request_id":"r1"}\n')
            controller = ControllerProbe(RequestFailure("rejected"))
            _handle_connection(server, controller, os.getuid())
            self.assertEqual(json.loads(peer.recv(4096)),
                             {"ok": False, "request_id": "r1",
                              "error": {"code": "rejected", "message": "rejected"}})
            self.assertEqual(controller.emergencies, 0)


if __name__ == "__main__":
    unittest.main()
