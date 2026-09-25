"""Protection status must use exact device/state observations, not substrings."""
import json
import unittest

from omarchy_wireguard.nftables import FirewallContext, expected_policy_from_echo, render
from omarchy_wireguard.system import HostSystem, SystemFailure
from test_system import FakeRunner, echoed_policy, observed_policy


UUID = "00000000-0000-0000-0000-000000000001"


def verification(active="activated\nwg0\n", handshakes="peer\t950\n"):
    context = FirewallContext(
        tunnel_interface="wg0", lan_prefixes=("192.168.1.0/24",),
        lan_resolvers=("192.168.1.1",), resolver_uid=992,
        physical_interfaces=("eth0",),
        lan_dns_links=(("eth0", ("192.168.1.1",)),),
        tunnel_dns=("10.0.0.1",))
    responses = {
        ("nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", UUID): active,
        ("wg", "show", "wg0", "fwmark"): "0x6f7467\n",
        ("ip", "-json", "route", "get", "1.1.1.1"): json.dumps([{"dev": "wg0"}]),
        ("ip", "-6", "-json", "route", "get", "2606:4700:4700::1111"): SystemFailure("no IPv6 route"),
        ("nft", "-j", "list", "table", "inet", "omarchy_wireguard"):
            observed_policy(render(context)),
        ("resolvectl", "dns", "wg0"): "Link 7 (wg0): 10.0.0.1\n",
        ("resolvectl", "domain", "wg0"): "Link 7 (wg0): ~.\n",
        ("resolvectl", "domain", "eth0"): "Link 2 (eth0): ~lan\n",
        ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1\n",
        ("resolvectl", "default-route", "eth0"): "Link 2 (eth0): no\n",
        ("wg", "show", "wg0", "latest-handshakes"): handshakes,
    }
    system = HostSystem(FakeRunner(responses))
    system.expected_firewall = expected_policy_from_echo(echoed_policy(render(context)))
    return system.verify(UUID, "wg0", now=1000, firewall_context=context)


class VerificationIdentityTests(unittest.TestCase):
    def test_deactivated_does_not_match_activated(self):
        result = verification(active="deactivated\nwg0\n")
        self.assertFalse(result.checks["profile_interface"])
        self.assertFalse(result.ok)

    def test_exact_active_device_remains_valid(self):
        self.assertTrue(verification().ok)

    def test_interface_substrings_and_extra_devices_are_not_accepted(self):
        for devices in ("wg01", "other-wg0", "wg0,eth0", "wg0\neth0", ""):
            with self.subTest(devices=devices):
                result = verification(active="activated\n" + devices + "\n")
                self.assertFalse(result.checks["profile_interface"])
                self.assertFalse(result.ok)

    def test_normal_rekey_interval_is_fresh(self):
        # WireGuard rekeys a healthy session about every 120 seconds.
        for age in (121, 125, 150, 180):
            with self.subTest(age=age):
                result = verification(handshakes=f"peer\t{1000 - age}\n")
                self.assertTrue(result.checks["handshake_fresh"])
                self.assertTrue(result.ok)

    def test_handshake_past_reject_after_time_is_stale(self):
        # After 180 seconds WireGuard itself refuses to use the session keys.
        for age in (181, 300):
            with self.subTest(age=age):
                result = verification(handshakes=f"peer\t{1000 - age}\n")
                self.assertFalse(result.checks["handshake_fresh"])
                self.assertFalse(result.ok)

    def test_future_handshake_is_not_fresh(self):
        result = verification(handshakes="peer\t1001\n")
        self.assertFalse(result.checks["handshake_fresh"])
        self.assertFalse(result.ok)


if __name__ == "__main__":
    unittest.main()
