import json
import re
import unittest

import omarchy_wireguard.nftables as nftables
from omarchy_wireguard.nftables import FirewallContext, FirewallError, render


class FirewallTests(unittest.TestCase):
    @staticmethod
    def observed_policy(rules, *, extra_comment=None, drop_forward=False, reverse=False):
        signed = []
        chain = None
        for line in rules.splitlines():
            if line.strip().startswith("chain "):
                chain = line.strip().split()[1]
            match = re.search(r'comment "(owg:[^"]+)"', line)
            if match:
                signed.append((chain, match.group(1)))
        if extra_comment:
            signed.insert(1, ("output", extra_comment))
        if reverse:
            signed.reverse()
        objects = [
            {"metainfo": {"json_schema_version": 1}},
            {"table": {"family": "inet", "name": "omarchy_wireguard", "handle": 1}},
            {"chain": {"family": "inet", "table": "omarchy_wireguard", "name": "output",
                       "handle": 2, "type": "filter", "hook": "output", "prio": -10,
                       "policy": "drop"}},
        ]
        if not drop_forward:
            objects.append({"chain": {"family": "inet", "table": "omarchy_wireguard",
                                      "name": "forward", "handle": 3, "type": "filter",
                                      "hook": "forward", "prio": -10, "policy": "drop"}})
        for index, (chain, comment) in enumerate(signed):
            objects.append({"rule": {"family": "inet", "table": "omarchy_wireguard",
                                     "chain": chain,
                                     "handle": index + 4, "comment": comment,
                                     "expr": [{"counter": {"packets": index, "bytes": index * 10}}]}})
        return json.dumps({"nftables": objects})

    @classmethod
    def echoed_policy(cls, rules):
        observed = json.loads(cls.observed_policy(rules))["nftables"]
        return json.dumps({"nftables": [
            {"add": entry} for entry in observed
            if next(iter(entry)) in {"table", "chain", "rule"}
        ]})

    def test_structured_policy_verification_requires_exact_signed_rule_order(self):
        self.assertTrue(hasattr(nftables, "observed_policy_matches"))
        rules = render(FirewallContext(physical_interfaces=("eth0",)))
        expected = nftables.expected_policy_from_echo(self.echoed_policy(rules))
        exact = self.observed_policy(rules)
        self.assertTrue(nftables.observed_policy_matches(exact, expected))
        self.assertFalse(nftables.observed_policy_matches(
            self.observed_policy(rules, extra_comment="owg:0000000000000000:accept everything"), expected))
        self.assertFalse(nftables.observed_policy_matches(
            self.observed_policy(rules, drop_forward=True), expected))
        self.assertFalse(nftables.observed_policy_matches(
            self.observed_policy(rules, reverse=True), expected))

        tampered = json.loads(exact)
        first_rule = next(entry["rule"] for entry in tampered["nftables"] if "rule" in entry)
        first_rule["expr"] = [{"accept": None}]
        self.assertFalse(nftables.observed_policy_matches(json.dumps(tampered), expected))

    def test_static_quarantine_has_no_discovery_dependent_exceptions(self):
        self.assertTrue(hasattr(nftables, "render_quarantine"))
        rules = nftables.render_quarantine()
        self.assertEqual(rules.count("policy drop"), 2)
        self.assertIn('oifname "lo" accept', rules)
        for unsafe in ("DHCP", "mDNS", "SSDP", "WireGuard endpoints", "directly connected LAN"):
            self.assertNotIn(unsafe, rules)

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

    def test_only_resolved_can_use_plain_dns_on_the_lan(self):
        rules = render(FirewallContext(
            lan_prefixes=("192.168.4.0/24", "fd42::/64"),
            lan_resolvers=("192.168.4.1", "fd42::1"), resolver_uid=992,
            physical_interfaces=("eth0",), local_interfaces=("docker0",),
        ))
        lines = rules.splitlines()
        resolved4 = next(i for i, line in enumerate(lines)
                         if "meta skuid 992" in line and "ip daddr" in line)
        blocked4 = next(i for i, line in enumerate(lines)
                        if "block direct LAN DNS" in line and "ip daddr" in line)
        lan4 = next(i for i, line in enumerate(lines)
                    if "directly connected LAN" in line and "ip daddr" in line)
        self.assertLess(resolved4, blocked4)
        self.assertLess(blocked4, lan4)
        self.assertTrue(any("block guest direct LAN DNS" in line and "ip daddr" in line
                            for line in lines))
        self.assertTrue(any("block direct LAN DNS" in line and "ip6 daddr" in line
                            for line in lines))

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

    def test_renderer_rejects_public_and_default_equivalent_lan_prefixes(self):
        for prefix in ("0.0.0.0/0", "0.0.0.0/1", "128.0.0.0/1", "8.8.8.0/24",
                       "::/0", "::/1", "8000::/1", "2001:4860::/32"):
            with self.subTest(prefix=prefix), self.assertRaisesRegex(FirewallError, "LAN"):
                render(FirewallContext(lan_prefixes=(prefix,), physical_interfaces=("eth0",)))

    def test_forward_lan_rules_are_scoped_to_verified_physical_interfaces(self):
        rules = render(FirewallContext(
            lan_prefixes=("192.168.4.0/24",), physical_interfaces=("eth0", "wlan0"),
            local_interfaces=("docker0",),
        ))
        guest = next(line for line in rules.splitlines() if "local guests to LAN" in line)
        returned = next(line for line in rules.splitlines()
                        if "ct state established,related" in line and "192.168.4.0/24" in line)
        self.assertIn('oifname { "eth0", "wlan0" }', guest)
        self.assertIn('iifname { "eth0", "wlan0" }', returned)


if __name__ == "__main__":
    unittest.main()
