import unittest
from unittest.mock import patch

from omarchy_wireguard.daemon import _handle_connection, reconcile_early_firewall
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.protocol import ProtocolError


class Store:
    def __init__(self, state=None, error=None):
        self.state = state
        self.error = error

    def read(self, name, default):
        if self.error and name == "state.json":
            raise self.error
        if name == "state.json":
            return self.state
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

    def test_corrupt_or_unsafe_state_fails_closed(self):
        for store in (Store({"enabled": "yes"}), Store(error=RuntimeError("unsafe"))):
            system = System()
            reconcile_early_firewall(store, system)
            self.assertEqual((system.removed, system.applied), (0, 1))

    def test_protocol_rejection_ignores_disconnected_client(self):
        with patch("omarchy_wireguard.daemon.peer_credentials",
                   side_effect=ProtocolError("bad peer")), patch(
                       "omarchy_wireguard.daemon.send_response", side_effect=BrokenPipeError):
            _handle_connection(object(), object(), 1000)


if __name__ == "__main__":
    unittest.main()
