import unittest

from omarchy_wireguard.nftables import FirewallContext, FirewallError, render


class FirewallTests(unittest.TestCase):
    def test_fail_closed_has_output_and_forward_drop(self):
        rules = render(FirewallContext(physical_interfaces=("eth0",)))
        self.assertIn("table inet omarchy_wireguard", rules)
        self.assertEqual(rules.count("policy drop"), 2)
        self.assertIn("protect Docker and VM forwarding", rules)
        self.assertNotIn("ct state established,related accept", rules)

    def test_renders_only_exact_endpoints_and_explicit_alfred_routes(self):
        rules = render(FirewallContext(
            tunnel_interface="wg0", endpoints=(("198.51.100.4", 51820),),
            wireguard_fwmark=0x6F7467,
            lan_prefixes=("192.168.4.0/24",), lan_resolvers=("192.168.4.1",), resolver_uid=992,
            physical_interfaces=("eth0",), alfred_interface="alfred-vpn",
            alfred_endpoints=(("203.0.113.9", 12345),), alfred_routes=("10.7.0.0/16",),
            local_interfaces=("docker0", "virbr0"),
        ))
        for expected in ("198.51.100.4 . 51820", "203.0.113.9 . 12345", "10.7.0.0/16",
                         "192.168.4.1", 'oifname "wg0"', 'oifname "alfred-vpn"'):
            self.assertIn(expected, rules)
        self.assertNotIn("0.0.0.0/0", rules)
        self.assertIn("meta skuid 992", rules)
        self.assertIn("meta mark 0x6f7467", rules)
        self.assertIn("meta skuid 0", rules)
        self.assertIn("local bridge traffic", rules)
        self.assertIn("local guests to LAN", rules)
        self.assertIn("nd-router-solicit", rules)
        self.assertIn("nd-router-advert", rules)
        self.assertIn("nd-neighbor-solicit", rules)
        self.assertNotIn("echo-request", rules)
        self.assertNotIn("    ct state established,related accept", rules)
        for line in rules.splitlines():
            if "ct state established,related accept" in line:
                self.assertIn("oifname", line)
                self.assertTrue("saddr" in line or 'iifname "wg0"' in line or
                                'iifname "alfred-vpn"' in line)

    def test_rejects_injected_interface(self):
        with self.assertRaises(FirewallError):
            render(FirewallContext(tunnel_interface='wg0" accept'))
        with self.assertRaises(FirewallError):
            render(FirewallContext(endpoints=(("192.0.2.1", 70000),)))

    def test_endpoint_exceptions_require_underlay_and_wireguard_mark(self):
        with self.assertRaisesRegex(FirewallError, "physical"):
            render(FirewallContext(endpoints=(("192.0.2.1", 51820),),
                                    wireguard_fwmark=0x6F7467))
        with self.assertRaisesRegex(FirewallError, "fwmark"):
            render(FirewallContext(endpoints=(("192.0.2.1", 51820),),
                                   physical_interfaces=("eth0",)))
        with self.assertRaisesRegex(FirewallError, "physical"):
            render(FirewallContext(alfred_endpoints=(("192.0.2.2", 51820),)))


if __name__ == "__main__":
    unittest.main()
