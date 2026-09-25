import base64
import io
import os
import tempfile
import unittest
import warnings
import zipfile
from dataclasses import replace
from pathlib import Path

from omarchy_wireguard.controller import Controller, RequestFailure, network_context
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.storage import StateCommitError
from omarchy_wireguard.system import SystemFailure, Verification


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
        self.deleted = []
        self.events = []
        self.dns_configurations = 0
        self.verified_contexts = []
        self.dns_captures = 0
        self.restored_dns = []
        self.fail_dns_restore = False
        self.fail_deactivate = False
        self.fail_quarantine = False

    def apply_quarantine(self, timeout=10):
        self.events.append("quarantine")
        if self.fail_quarantine:
            raise SystemFailure("quarantine failed")

    def inspect_firewall_context(self, timeout=10):
        return FirewallContext(lan_prefixes=("192.168.1.0/24",), physical_interfaces=("eth0",),
                               resolver_uid=992)

    def apply_firewall(self, context, timeout=10):
        self.firewalls.append(context)
        self.events.append("firewall")

    def remove_firewall(self, timeout=10):
        self.removals += 1

    def capture_lan_dns(self, interfaces, timeout=10):
        if not interfaces:
            return ()
        self.dns_captures += 1
        return tuple((interface, ("~.",), True) for interface in interfaces)

    def restore_lan_dns(self, state, timeout=10):
        self.dns_restores += 1
        self.restored_dns.append(state)
        if self.fail_dns_restore:
            raise SystemFailure("DNS restore failed")

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
        if self.fail_deactivate:
            raise SystemFailure("deactivation failed")

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
        self.deleted.append(uuid)


class ControllerTests(unittest.TestCase):
    def setUp(self):
        self.now = 1000.0
        self.store = MemoryStore()
        self.system = FakeSystem()
        self.controller = Controller(self.store, self.system, clock=lambda: self.now,
                                     monotonic=lambda: self.now, sleeper=self._sleep)

    def _sleep(self, seconds):
        self.now += seconds

    def test_named_personal_import_bypasses_location_review(self):
        result = self.controller.handle("import", {
            "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "home.conf",
            "labels": {"home.conf": "Home exit"},
        })
        self.assertTrue(result["imported"])
        profile = next(item for item in self.controller.catalog if item["source_name"] == "home.conf")
        self.assertEqual(profile["label"], "Home exit")
        self.assertEqual(profile["role"], "internet-exit")
        self.assertEqual((profile["country"], profile["city"]), ("", ""))

    def test_path_import_is_rejected_before_side_effects(self):
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "home.conf"
            path.write_text(IMPORT_CONFIG)
            path.chmod(0o600)
            with self.assertRaisesRegex(RequestFailure, "descriptor"):
                self.controller.handle("import", {
                    "path": str(path),
                    "labels": {"home.conf": "Home exit"},
                })
        self.assertEqual(self.system.imported, [])

    def test_descriptor_import_uses_the_opened_object(self):
        controller = Controller(self.store, self.system, controller_uid=os.getuid(),
                                clock=lambda: self.now, monotonic=lambda: self.now,
                                sleeper=self._sleep)
        with tempfile.TemporaryDirectory() as temporary:
            path = Path(temporary) / "home.conf"
            path.write_text(IMPORT_CONFIG)
            path.chmod(0o600)
            descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
            try:
                path.rename(path.with_suffix(".old"))
                path.write_text("replacement")
                result = controller.handle("import", {
                    "source": "fd", "name": "home.conf",
                    "labels": {"home.conf": "Home exit"},
                }, source_fd=descriptor)
            finally:
                os.close(descriptor)
        self.assertTrue(result["imported"])
        self.assertEqual(self.system.imported[0][1].label, "Home exit")

    def test_successful_connect_updates_mru_and_persistence(self):
        result = self.controller.connect({"city": "Japan/Tokyo"})
        self.assertEqual(result["mode"], "connecting")
        self.assertEqual(result["retry_at"], self.now)
        self.assertEqual(self.system.activations, [])
        self.controller.tick()
        result = self.controller.status({})
        self.assertEqual(result["mode"], "connected")
        self.assertEqual(result["backend_version"], "0.2.0")
        self.assertEqual(result["protocol_version"], 2)
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
        self.assertEqual(self.system.dns_captures, 1)
        self.assertEqual(self.store.values["dns.json"], (("eth0", ("~.",), True),))
        self.assertEqual(self.system.firewalls[-1].lan_resolvers, ("192.168.1.2",))
        self.assertIs(self.system.verified_contexts[-1], self.controller.firewall_context)
        tunnel_dns = self.system.events.index("configure_tunnel_dns")
        connected_firewall = max(index for index, event in enumerate(self.system.events)
                                 if event == "firewall")
        self.assertLess(connected_firewall, tunnel_dns)

    def test_connect_requires_quarantine_before_enabled_intent_or_deactivation(self):
        self.system.fail_quarantine = True

        with self.assertRaisesRegex(SystemFailure, "quarantine failed"):
            self.controller.connect({"profile": PROFILE["id"]})

        self.assertFalse(self.controller.enabled)
        self.assertEqual(self.controller.mode, "disabled")
        self.assertEqual(self.system.deactivations, 0)
        self.assertNotIn("state.json", self.store.values)

    def test_connect_installs_quarantine_before_disrupting_the_direct_path(self):
        self.controller.connect({"profile": PROFILE["id"]})

        self.assertIn("quarantine", self.system.events)
        self.assertLess(self.system.events.index("quarantine"), self.system.events.index("firewall"))
        self.assertTrue(self.store.values["state.json"]["enabled"])

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

    def test_pause_clears_dns_snapshot_before_accepting_direct_dns_changes(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.controller.pause({"seconds": 10})
        self.assertEqual(self.store.values["dns.json"], [])

    def test_disconnect_keeps_fail_closed_policy_when_deactivation_fails(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.system.fail_deactivate = True
        with self.assertRaises(SystemFailure):
            self.controller.disconnect({})
        self.assertTrue(self.controller.enabled)
        self.assertEqual(self.controller.mode, "failed")
        self.assertEqual(self.system.removals, 0)

    def test_disconnect_preserves_unrelated_networks_by_api_contract(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        result = self.controller.disconnect({})
        self.assertEqual(result["mode"], "disabled")
        self.assertFalse(result["enabled"])
        self.assertEqual(self.system.removals, 1)
        self.assertEqual(self.system.dns_restores, 1)
        self.assertEqual(self.system.tunnel_dns_clears, 1)
        self.assertEqual(self.system.restored_dns[-1], (("eth0", ("~.",), True),))
        self.assertEqual(self.store.values["dns.json"], [])

    def test_disconnect_keeps_fail_closed_policy_when_dns_restore_fails(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        self.system.fail_dns_restore = True
        with self.assertRaises(SystemFailure):
            self.controller.disconnect({})
        self.assertTrue(self.controller.enabled)
        self.assertEqual(self.controller.mode, "failed")
        self.assertEqual(self.system.removals, 0)
        self.assertTrue(self.store.values["state.json"]["enabled"])
        self.assertNotEqual(self.store.values["dns.json"], [])

    def test_disabled_boot_removes_firewall_while_enabled_boot_fails_closed(self):
        disabled_store = MemoryStore({"profiles.json": [dict(PROFILE)],
                                      "dns.json": [["eth0", ["~."], True]]})
        disabled_system = FakeSystem()
        Controller(disabled_store, disabled_system, clock=lambda: self.now,
                   monotonic=lambda: self.now).boot()
        self.assertEqual(disabled_system.removals, 1)
        self.assertEqual(disabled_system.restored_dns[-1], (("eth0", ("~.",), True),))
        self.assertEqual(disabled_store.values["dns.json"], [])
        enabled_store = MemoryStore({"profiles.json": [dict(PROFILE)],
                                     "state.json": {"enabled": True, "target": "Japan/Tokyo", "mru": []}})
        enabled_system = FakeSystem()
        Controller(enabled_store, enabled_system, clock=lambda: self.now,
                   monotonic=lambda: self.now).boot()
        self.assertTrue(enabled_system.firewalls)
        self.assertEqual(enabled_system.removals, 0)

    def test_controller_rejects_malformed_existing_state(self):
        for state in ({}, {"enabled": True, "target": "", "mru": []}):
            with self.subTest(state=state):
                store = MemoryStore({"profiles.json": [dict(PROFILE)], "state.json": state})
                with self.assertRaises(RequestFailure):
                    Controller(store, FakeSystem())
        store = MemoryStore({"profiles.json": [dict(PROFILE)],
                             "dns.json": [["eth0;evil", ["~."], True]]})
        with self.assertRaises(RequestFailure):
            Controller(store, FakeSystem())

    def test_additive_import_preserves_failed_target_and_retry(self):
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
        self.assertEqual(self.system.firewalls, [])
        self.assertEqual(self.controller.catalog[0]["uuid"], PROFILE["uuid"])

    def test_additive_import_preserves_healthy_tunnel_and_old_profiles(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        before = self.controller.status({})
        old_catalog = list(self.controller.catalog)
        old_context = self.controller.firewall_context
        deactivations = self.system.deactivations
        self.system.managed_profiles = lambda: {"uuid-1": "old", "orphan-uuid": "orphan"}
        result = self.controller.import_profiles({
            "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf"})
        self.assertEqual(result["status"], before)
        self.assertEqual(self.controller.catalog[:1], old_catalog)
        self.assertEqual(len(self.controller.catalog), 2)
        self.assertEqual(self.store.values["profiles.json"], self.controller.catalog)
        self.assertIs(self.controller.firewall_context, old_context)
        self.assertEqual(self.system.deactivations, deactivations)
        self.assertEqual(self.system.activations, ["uuid-1"])
        self.assertEqual(self.system.deleted, [])

    def test_duplicate_source_names_are_rejected_before_side_effects(self):
        for names in (("jp-tokyo.conf",), ("us-seattle.conf", "us-seattle.conf")):
            archive = io.BytesIO()
            with zipfile.ZipFile(archive, "w") as zipped:
                for name in names:
                    # Duplicate members are legal ZIP input, but not a legal import batch.
                    with warnings.catch_warnings():
                        warnings.simplefilter("ignore", UserWarning)
                        zipped.writestr(name, IMPORT_CONFIG)
            with self.subTest(names=names), self.assertRaisesRegex(RequestFailure, "duplicate source_name"):
                self.controller.handle("import", {
                    "data": base64.b64encode(archive.getvalue()).decode(), "name": "profiles.zip"})
            self.assertEqual(self.system.imported, [])
            self.assertEqual(self.system.deleted, [])
            self.assertEqual(self.system.deactivations, 0)
            self.assertEqual(len(self.controller.catalog), 1)

    def test_new_ids_do_not_collide_across_batches_or_restart(self):
        old = dict(self.controller.catalog[0])
        for name in ("jp-tokyo-2.conf", "jp-tokyo-3.conf"):
            self.controller.import_profiles({
                "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": name,
                "locations": {name: {"country": "Japan", "city": "Tokyo"}},
            })
            self.controller = Controller(self.store, self.system)
        self.assertEqual(self.controller.catalog[0], old)
        identifiers = [item["id"] for item in self.controller.catalog]
        self.assertEqual(len(set(identifiers)), 3)
        self.assertEqual(len({item[2] for item in self.system.imported}), 2)

    def test_import_does_not_reuse_orphan_managed_connection_names(self):
        self.system.managed_profiles = lambda: {
            "orphan-uuid": "omarchy-wireguard-united-states-seattle-1"}
        self.controller.import_profiles({
            "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf"})
        self.assertNotEqual(self.system.imported[0][2], "omarchy-wireguard-united-states-seattle-1")
        self.assertEqual(self.system.deleted, [])

    def test_catalog_write_failure_rolls_back_new_profiles_without_publishing(self):
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        before = self.controller.status({})
        old_catalog = list(self.controller.catalog)
        persisted = self.store.values["profiles.json"]
        deactivations = self.system.deactivations
        def fail_write(name, value):
            self.assertEqual(self.controller.catalog, old_catalog)
            raise OSError("disk full")
        self.store.write = fail_write
        with self.assertRaisesRegex(RequestFailure, "persist|import"):
            self.controller.handle("import", {
                "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf"})
        self.assertEqual(self.controller.catalog, old_catalog)
        self.assertEqual(self.store.values["profiles.json"], persisted)
        self.assertEqual(self.system.deleted, ["new-0"])
        self.assertEqual(self.controller.status({}), before)
        self.assertEqual(self.system.deactivations, deactivations)

    def test_import_policy_persistence_failure_preserves_old_catalog_and_policy(self):
        for failing_name in ("network.json", "profiles.json"):
            with self.subTest(failing_name=failing_name):
                store = MemoryStore({"profiles.json": [dict(PROFILE)], "network.json": {}})
                system = FakeSystem()
                controller = Controller(store, system)
                old_catalog = list(controller.catalog)
                write = store.write
                def fail_write(name, value):
                    if name == failing_name:
                        raise OSError("disk full")
                    write(name, value)
                store.write = fail_write
                with self.assertRaisesRegex(RequestFailure, "persist|import"):
                    controller.handle("import", {
                        "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(),
                        "name": "us-seattle.conf", "network": {"lan_resolvers": ["192.168.1.1"]}})
                self.assertEqual(controller.catalog, old_catalog)
                self.assertEqual(store.values["profiles.json"], [PROFILE])
                self.assertEqual(controller.network_policy, {})
                self.assertEqual(store.values["network.json"], {})
                self.assertEqual(system.deleted, ["new-0"])
                self.assertEqual(system.deactivations, 0)

    def test_committed_catalog_is_not_rolled_back_on_durability_error(self):
        write = self.store.write
        def commit_then_fail(name, value):
            write(name, value)
            if name == "profiles.json":
                raise StateCommitError("fsync failed")
        self.store.write = commit_then_fail
        with self.assertRaisesRegex(RequestFailure, "committed.*durability"):
            self.controller.handle("import", {
                "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf"})
        self.assertEqual(len(self.store.values["profiles.json"]), 2)
        self.assertEqual(self.controller.catalog, self.store.values["profiles.json"])
        self.assertEqual(self.system.deleted, [])

    def test_network_rename_error_restores_policy_before_rolling_back_import(self):
        write = self.store.write
        def commit_policy_then_fail(name, value):
            write(name, value)
            if name == "network.json" and value:
                raise StateCommitError("fsync failed")
        self.store.write = commit_policy_then_fail
        with self.assertRaises(RequestFailure):
            self.controller.handle("import", {
                "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf",
                "network": {"lan_resolvers": ["192.168.1.1"]}})
        self.assertEqual(self.store.values.get("network.json", {}), {})
        self.assertEqual(self.controller.network_policy, {})
        self.assertEqual(self.system.deleted, ["new-0"])
        self.assertEqual(len(self.controller.catalog), 1)

    def test_failed_policy_rollback_still_cleans_new_nm_profiles(self):
        write = self.store.write
        def fail_catalog_and_restore(name, value):
            if name == "profiles.json" or (name == "network.json" and not value):
                raise OSError("disk unavailable")
            write(name, value)
        self.store.write = fail_catalog_and_restore
        with self.assertRaisesRegex(RequestFailure, "rollback incomplete"):
            self.controller.handle("import", {
                "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "us-seattle.conf",
                "network": {"lan_resolvers": ["192.168.1.1"]}})
        self.assertEqual(self.system.deleted, ["new-0"])
        self.assertEqual(len(self.controller.catalog), 1)
        self.assertEqual(self.controller.network_policy, {})
        self.assertEqual(self.system.deactivations, 0)

    def test_named_profile_without_geography_is_not_a_legacy_city(self):
        self.controller.import_profiles({
            "data": base64.b64encode(IMPORT_CONFIG.encode()).decode(), "name": "home.conf",
            "labels": {"home.conf": "Home"}})
        profile = self.controller.catalog[-1]
        self.assertEqual([item["id"] for item in self.controller.list_profiles({})["cities"]], ["Japan/Tokyo"])
        with self.assertRaisesRegex(RequestFailure, "unknown city"):
            self.controller.connect({"city": "/"})
        result = self.controller.connect({"profile": profile["id"]})
        self.assertIsNone(result["target_city"])
        self.assertEqual(result["target_profile"]["label"], "Home")
        self.controller.tick()
        self.assertEqual(self.system.activations, [profile["uuid"]])

    def test_profile_target_selects_exact_id_despite_city_mru(self):
        self.controller.catalog.append({**PROFILE_2, "label": "Other exit", "role": "internet-exit"})
        self.controller.mru = [PROFILE["id"]]
        result = self.controller.connect({"profile": PROFILE_2["id"]})
        self.assertEqual(result["target"], "profile:" + PROFILE_2["id"])
        self.assertEqual(result["target_profile"]["id"], PROFILE_2["id"])
        self.assertEqual(result["target_profile"]["label"], "Other exit")
        self.assertEqual(self.store.values["state.json"]["target"], "profile:" + PROFILE_2["id"])
        self.controller.tick()
        self.assertEqual(self.system.activations, [PROFILE_2["uuid"]])
        self.assertEqual(self.controller.status({})["current"]["id"], PROFILE_2["id"])

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

    def test_list_normalizes_legacy_labels_and_roles_without_rewriting_ids(self):
        listed = self.controller.list_profiles({})
        self.assertEqual(listed.get("profiles"), [{
            "id": PROFILE["id"], "label": "jp-tokyo", "role": "internet-exit",
            "source_name": PROFILE["source_name"], "country": "Japan", "city": "Tokyo",
        }])
        self.assertEqual(self.controller.catalog[0]["label"], "jp-tokyo")
        self.assertEqual(self.controller.catalog[0]["role"], "internet-exit")
        self.assertEqual(self.controller.catalog[0]["uuid"], PROFILE["uuid"])
        self.controller.connect({"city": "Japan/Tokyo"})
        self.controller.tick()
        current = self.controller.status({})["current"]
        self.assertEqual(current["label"], "jp-tokyo")
        self.assertEqual(current["role"], "internet-exit")

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

    def test_alfred_routes_are_private_and_never_default_equivalent(self):
        accepted = network_context({
            "alfred": {"interface": "alfred-vpn", "endpoints": [],
                       "routes": ["10.20.0.0/16", "192.168.50.0/24", "fd42::/64"]},
        }, FirewallContext())
        self.assertEqual(accepted.alfred_routes,
                         ("10.20.0.0/16", "192.168.50.0/24", "fd42::/64"))

        for route in ("0.0.0.0/0", "::/0", "8.8.8.0/24", "2001:4860::/32",
                      "127.0.0.0/8", "169.254.0.0/16", "fe80::/10"):
            with self.subTest(route=route), self.assertRaisesRegex(RequestFailure, "private"):
                network_context({
                    "alfred": {"interface": "alfred-vpn", "endpoints": [], "routes": [route]},
                }, FirewallContext())


if __name__ == "__main__":
    unittest.main()
