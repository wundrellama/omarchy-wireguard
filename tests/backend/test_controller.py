import base64
import unittest
from dataclasses import replace

from omarchy_torguard.controller import Controller, RequestFailure, network_context
from omarchy_torguard.nftables import FirewallContext
from omarchy_torguard.system import SystemFailure, Verification


PROFILE = {"id": "japan-tokyo-1", "uuid": "uuid-1", "source_name": "jp-tokyo.conf",
           "country": "Japan", "city": "Tokyo", "city_key": "Japan/Tokyo",
           "endpoint_host": "192.0.2.4", "endpoint_port": 51820}
PROFILE_2 = {**PROFILE, "id": "japan-tokyo-2", "uuid": "uuid-2",
             "source_name": "jp-tokyo-2.conf", "endpoint_host": "192.0.2.5"}
IMPORT_CONFIG = """[Interface]
PrivateKey = secret
Address = 10.0.0.2/32
DNS = 10.8.0.1
[Peer]
PublicKey = public
AllowedIPs = 0.0.0.0/0, ::/0
Endpoint = 192.0.2.8:51820
"""


class MemoryStore:
    def __init__(self, values=None):
        self.values = values or {"profiles.json": [dict(PROFILE)]}

    def read(self, name, default):
        return self.values.get(name, default)

    def write(self, name, value):
        self.values[name] = value


class FakeSystem:
    def __init__(self):
        self.fail_activate = False
        self.verification = Verification(True, {"handshake_fresh": True}, "ok")
        self.verification_results = []
        self.verify_calls = 0
        self.firewalls = []
        self.deactivations = 0
        self.removals = 0
        self.dns_restores = 0
        self.tunnel_dns_clears = 0
        self.fail_uuids = set()
        self.activations = []
        self.imported = []
        self.events = []
        self.dns_configurations = 0
        self.verified_contexts = []

    def inspect_firewall_context(self, timeout=10):
        return FirewallContext(lan_prefixes=("192.168.1.0/24",), physical_interfaces=("eth0",),
                               resolver_uid=992)

    def apply_firewall(self, context, timeout=10):
        self.firewalls.append(context)
        self.events.append("firewall")

    def remove_firewall(self, timeout=10):
        self.removals += 1

    def restore_lan_dns(self, timeout=10):
        self.dns_restores += 1

    def configure_lan_dns(self, context, timeout=10):
        self.events.append("configure_lan_dns")
        self.dns_configurations += 1
        resolver = f"192.168.1.{self.dns_configurations}"
        return replace(context, lan_resolvers=(resolver,),
                       lan_dns_links=(("eth0", (resolver,)),))

    def configure_tunnel_dns(self, uuid, interface, timeout=10):
        self.events.append("configure_tunnel_dns")
        return ("1.1.1.1",)

    def clear_tunnel_dns(self, interface, timeout=10):
        self.events.append("clear_tunnel_dns")
        self.tunnel_dns_clears += 1

    def deactivate_managed(self):
        self.deactivations += 1

    def resolve_endpoint(self, host, port, timeout=10):
        return ((host, port),)

    def activate(self, uuid, timeout):
        self.events.append("activate")
        self.activations.append(uuid)
        if self.fail_activate or uuid in self.fail_uuids:
            raise SystemFailure("activation failed")
        return "wg0"

    def verify(self, uuid, interface, now=None, timeout=10, firewall_context=None):
        self.verify_calls += 1
        self.verified_contexts.append(firewall_context)
        if self.verification_results:
            return self.verification_results.pop(0)
        return self.verification

    def managed_profiles(self):
        return {}

    def import_profile(self, profile, name):
        uuid = f"new-{len(self.imported)}"
        self.imported.append((uuid, profile, name))
        return uuid

    def delete_profile(self, uuid):
        pass


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.store = MemoryStore()
        self.system = FakeSystem()
        self.controller = Controller(self.store, self.system, clock=lambda: self.now,
                                     monotonic=lambda: self.now, sleeper=self._sleep)

    def _sleep(self, seconds):
        self.now += seconds

    def test_successful_connect_updates_mru_and_persistence(self):
        result = self.controller.connect({"city": "Japan/Tokyo"})
        self.assertEqual(result["mode"], "connecting")
        self.assertEqual(result["retry_at"], self.now)
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        result = self.controller.status({})
        self.assertEqual(result["mode"], "connected")
        self.assertEqual(self.controller.mru, ["japan-tokyo-1"])
        self.assertTrue(self.store.values["state.json"]["enabled"])
        self.assertEqual(self.system.firewalls[-1].tunnel_interface, "wg0")
        self.assertEqual(result["current"]["country"], "Japan")
        self.assertEqual(result["target_city"]["city"], "Tokyo")
        self.assertLess(self.system.events.index("configure_lan_dns"),
                        self.system.events.index("activate"))
        dns_events = [index for index, event in enumerate(self.system.events)
                      if event == "configure_lan_dns"]
        activation = self.system.events.index("activate")
        self.assertEqual(len(dns_events), 2)
        self.assertLess(dns_events[0], activation)
        self.assertGreater(dns_events[1], activation)
        self.assertEqual(self.controller.firewall_context.lan_resolvers, ("192.168.1.2",))
        self.assertEqual(self.controller.firewall_context.tunnel_dns, ("1.1.1.1",))
        self.assertEqual(self.system.firewalls[-1].lan_resolvers, ("192.168.1.2",))
        self.assertIs(self.system.verified_contexts[-1], self.controller.firewall_context)
        tunnel_dns = self.system.events.index("configure_tunnel_dns")
        connected_firewall = max(index for index, event in enumerate(self.system.events)
                                 if event == "firewall")
        self.assertLess(connected_firewall, tunnel_dns)

    def test_transient_verification_failure_recovers_within_city_budget(self):
        transient = Verification(False, {"handshake_fresh": False}, "handshake not ready")
        success = Verification(True, {"handshake_fresh": True}, "ok")
        self.system.verification_results = [transient, success]
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.assertEqual(self.controller.mode, "connected")
        self.assertEqual(self.system.verify_calls, 2)
        self.assertEqual(self.now, 1000.5)
        self.assertEqual(self.controller.last_checks, {"handshake_fresh": True})
        self.assertIsNotNone(self.controller.firewall_context)

    def test_verification_polling_uses_one_bounded_city_budget(self):
        self.system.verification = Verification(False, {"handshake_fresh": False},
                                                "handshake still pending")
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.assertEqual(self.controller.mode, "failed")
        self.assertLessEqual(self.now - 1000.0, 20.0)
        self.assertLessEqual(self.system.verify_calls, 41)
        self.assertEqual(self.controller.last_checks, {"handshake_fresh": False})
        self.assertEqual(self.controller.last_error, "handshake still pending")
        self.assertEqual(self.system.tunnel_dns_clears, 1)

    def test_failure_is_fail_closed_and_does_not_update_mru(self):
        self.system.fail_activate = True
        result = self.controller.connect({"city": "Japan/Tokyo"})
        self.assertEqual(result["mode"], "connecting")
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        result = self.controller.status({})
        self.assertEqual(result["mode"], "failed")
        self.assertEqual(result["retry_at"], 1002.0)
        self.assertEqual(self.controller.mru, [])
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)

    def test_stale_connected_state_enters_retry(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.system.verification = Verification(False, {"handshake_fresh": False}, "stale")
        self.controller.tick()
        self.assertEqual(self.controller.mode, "failed")
        self.assertGreater(self.system.deactivations, 0)

    def test_pause_expires_and_boot_does_not_restore_pause(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.assertEqual(self.controller.pause({"seconds": 10})["mode"], "paused")
        self.now += 10
        self.controller.tick()
        self.assertEqual(self.controller.mode, "connecting")
        self.assertIsNone(self.controller.current)
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
        self.controller.tick()
        self.assertEqual(self.controller.mode, "connected")
        self.assertGreater(self.system.removals, 0)
        self.assertTrue(self.store.values["state.json"]["enabled"])
        self.assertEqual(self.store.values["state.json"]["target"], "Japan/Tokyo")
        rebooted = Controller(self.store, FakeSystem(), clock=lambda: self.now, monotonic=lambda: self.now)
        self.assertEqual(rebooted.mode, "connecting")
        self.assertIsNone(rebooted.pause_until)

    def test_disconnect_preserves_unrelated_networks_by_api_contract(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        result = self.controller.disconnect({})
        self.assertEqual(result["mode"], "disabled")
        self.assertFalse(result["enabled"])
        self.assertEqual(self.system.removals, 1)
        self.assertEqual(self.system.dns_restores, 1)
        self.assertEqual(self.system.tunnel_dns_clears, 1)

    def test_disabled_boot_removes_firewall_while_enabled_boot_fails_closed(self):
        self.controller.boot()
        self.assertEqual(self.system.removals, 1)
        enabled_store = MemoryStore({"profiles.json": [dict(PROFILE)],
                                     "state.json": {"enabled": True, "target": "Japan/Tokyo", "mru": []}})
        enabled_system = FakeSystem()
        Controller(enabled_store, enabled_system, clock=lambda: self.now,
                   monotonic=lambda: self.now).boot()
        self.assertTrue(enabled_system.firewalls)
        self.assertEqual(enabled_system.removals, 0)

    def test_controller_rejects_malformed_existing_state(self):
        store = MemoryStore({"profiles.json": [dict(PROFILE)], "state.json": {}})
        with self.assertRaises(RequestFailure):
            Controller(store, FakeSystem())

    def test_missing_selected_city_after_import_stays_enabled_and_failed(self):
        self.controller.enabled = True
        self.controller.target = "Japan/Tokyo"
        self.controller.mode = "failed"
        args = {"data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf",
                "locations": {"us-seattle.conf": {"country": "United States", "city": "Seattle"}}}
        result = self.controller.import_profiles(args)
        self.assertTrue(result["imported"])
        self.assertTrue(self.controller.enabled)
        self.assertEqual(self.controller.target, "Japan/Tokyo")
        self.assertEqual(self.controller.mode, "failed")
        self.assertIsNone(self.controller.retry_at)
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
        self.assertTrue(self.store.values["state.json"]["enabled"])
        self.assertEqual(self.store.values["state.json"]["target"], "Japan/Tokyo")

    def test_enabled_reimport_schedules_attempt_without_activating(self):
        self.controller.enabled = True
        self.controller.target = "Japan/Tokyo"
        self.controller.mode = "failed"
        args = {"data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "jp-tokyo.conf",
                "locations": {"jp-tokyo.conf": {"country": "Japan", "city": "Tokyo"}}}
        result = self.controller.import_profiles(args)
        self.assertEqual(result["status"]["mode"], "connecting")
        self.assertEqual(result["status"]["retry_at"], self.now)
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        self.assertEqual(self.controller.mode, "connected")
        self.assertEqual(self.system.activations, ["new-0"])

    def test_same_city_failover_and_mru_preference(self):
        self.controller.catalog = [dict(PROFILE), dict(PROFILE_2)]
        self.system.fail_uuids = {"uuid-1"}
        self.controller.connect({"city": "Japan/Tokyo"})
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        self.assertEqual(self.system.activations, ["uuid-1", "uuid-2"])
        self.assertEqual(self.controller.mru[0], "japan-tokyo-2")
        self.system.activations.clear()
        self.system.fail_uuids.clear()
        result = self.controller.retry({})
        self.assertEqual(result["mode"], "connecting")
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        self.assertEqual(self.system.activations[0], "uuid-2")

    def test_list_has_normalized_locations_without_endpoints(self):
        listed = self.controller.list_profiles({})
        self.assertEqual(listed["cities"][0]["country"], "Japan")
        self.assertEqual(listed["cities"][0]["city"], "Tokyo")
        self.assertNotIn("endpoint_host", str(listed))

    def test_strict_arguments(self):
        with self.assertRaises(RequestFailure):
            self.controller.connect({"city": "Japan/Tokyo", "extra": True})
        with self.assertRaises(RequestFailure):
            self.controller.pause({"seconds": 601})

    def test_explicit_network_policy(self):
        context = network_context({
            "lan_resolvers": ["192.168.1.1"],
            "alfred": {"interface": "alfred-vpn", "endpoints": [["203.0.113.2", 51820]],
                       "routes": ["10.20.0.0/16"]},
        }, FirewallContext(lan_prefixes=("192.168.1.0/24",), physical_interfaces=("eth0",),
                           resolver_uid=992))
        self.assertEqual(context.alfred_interface, "alfred-vpn")
        self.assertEqual(context.alfred_endpoints, (("203.0.113.2", 51820),))
        with self.assertRaises(RequestFailure):
            network_context({"alfred": {"interface": "wg-any", "endpoints": [], "routes": []}},
                            FirewallContext())


if __name__ == "__main__":
    unittest.main()
