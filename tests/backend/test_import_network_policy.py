"""Imports must not change network policy while VPN intent is enabled."""
import base64
import unittest
from copy import deepcopy
from unittest.mock import patch

from omarchy_wireguard.controller import Controller, RequestFailure
from omarchy_wireguard.importer import decode_payload
from test_controller import FakeSystem, IMPORT_CONFIG, MemoryStore, PROFILE


POLICY = {"alfred": {"interface": "alfred-vpn",
                     "endpoints": [["203.0.113.2", 51820]],
                     "routes": ["10.90.0.0/16"]}}
ENABLED_MODES = ("connected", "connecting", "failed", "paused")


def import_args(**extra):
    return {"data": base64.b64encode(IMPORT_CONFIG.encode()).decode(),
            "name": "us-seattle.conf", **extra}


def controller_state(controller):
    return deepcopy({key: value for key, value in vars(controller).items()
                     if key not in {"store", "system", "clock", "monotonic", "sleeper"}})


class ImportNetworkPolicyTests(unittest.TestCase):
    def make_controller(self, mode):
        store = MemoryStore({"profiles.json": [dict(PROFILE)], "network.json": deepcopy(POLICY)})
        system = FakeSystem()
        controller = Controller(store, system, clock=lambda: 1000, monotonic=lambda: 1000)
        if mode != "disabled":
            system.fail_activate = mode == "failed"
            controller.connect({"profile": PROFILE["id"]})
            if mode != "connecting":
                controller.tick()
            if mode == "paused":
                controller.pause({"seconds": 10})
        self.assertEqual(controller.mode, mode)
        self.assertEqual(controller.enabled, mode != "disabled")
        return controller, store, system

    def test_changed_policy_is_rejected_without_side_effects_in_all_enabled_modes(self):
        for mode in ENABLED_MODES:
            with self.subTest(mode=mode):
                controller, store, system = self.make_controller(mode)
                before = controller_state(controller)
                persisted = deepcopy(store.values)
                system_before = deepcopy(vars(system))
                context = controller.firewall_context
                if mode == "connected":
                    self.assertEqual(context.alfred_routes, ("10.90.0.0/16",))
                with patch("omarchy_wireguard.controller.decode_payload", wraps=decode_payload) as decode, \
                        patch.object(system, "managed_profiles", wraps=system.managed_profiles) as managed, \
                        patch.object(store, "write", wraps=store.write) as write:
                    with self.assertRaisesRegex(RequestFailure, "network policy.*enabled"):
                        controller.handle("import", import_args(network={}))
                    decode.assert_not_called()
                    managed.assert_not_called()
                    write.assert_not_called()
                self.assertEqual(controller_state(controller), before)
                self.assertEqual(store.values, persisted)
                self.assertEqual(vars(system), system_before)
                self.assertIs(controller.firewall_context, context)
                if mode == "connected":
                    controller.tick()
                    self.assertEqual(controller.mode, "connected")
                    self.assertIs(system.verified_contexts[-1], context)

    def test_omitted_and_identical_policy_imports_preserve_enabled_runtime(self):
        for mode in ENABLED_MODES:
            for explicit in (False, True):
                with self.subTest(mode=mode, explicit=explicit):
                    controller, store, system = self.make_controller(mode)
                    before = controller_state(controller)
                    persisted = deepcopy(store.values)
                    system_before = deepcopy(vars(system))
                    extra = {"network": deepcopy(POLICY)} if explicit else {}
                    result = controller.handle("import", import_args(**extra))
                    self.assertTrue(result["imported"])
                    self.assertEqual(result["profiles"], 1)
                    after = controller_state(controller)
                    self.assertEqual(after.pop("catalog")[:-1], before.pop("catalog"))
                    self.assertEqual(after, before)
                    self.assertEqual(store.values["profiles.json"], controller.catalog)
                    self.assertEqual({key: value for key, value in store.values.items()
                                      if key != "profiles.json"},
                                     {key: value for key, value in persisted.items()
                                      if key != "profiles.json"})
                    system_after = deepcopy(vars(system))
                    self.assertEqual(len(system_after.pop("imported")), 1)
                    self.assertEqual(system_before.pop("imported"), [])
                    self.assertEqual(system_after, system_before)

    def test_disabled_import_can_change_network_policy(self):
        controller, store, system = self.make_controller("disabled")
        result = controller.handle("import", import_args(network={}))
        self.assertTrue(result["imported"])
        self.assertEqual(controller.network_policy, {})
        self.assertEqual(store.values["network.json"], {})
        self.assertEqual(store.values["profiles.json"], controller.catalog)
        self.assertEqual(len(controller.catalog), 2)
        self.assertEqual(controller.mode, "disabled")
        self.assertFalse(controller.enabled)
        self.assertEqual(system.events, [])

    def test_policy_validation_precedes_enabled_guard_and_payload_decode(self):
        controller, store, system = self.make_controller("connected")
        before = controller_state(controller)
        persisted = deepcopy(store.values)
        system_before = deepcopy(vars(system))
        with patch("omarchy_wireguard.controller.decode_payload", wraps=decode_payload) as decode:
            with self.assertRaisesRegex(RequestFailure, "invalid network policy"):
                controller.handle("import", import_args(network={"unknown": True}))
            decode.assert_not_called()
        self.assertEqual(controller_state(controller), before)
        self.assertEqual(store.values, persisted)
        self.assertEqual(vars(system), system_before)


if __name__ == "__main__":
    unittest.main()
