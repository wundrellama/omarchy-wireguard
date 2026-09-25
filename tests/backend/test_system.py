import json
import os
import pwd
import re
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from omarchy_wireguard.importer import Profile
from omarchy_wireguard.nftables import (FirewallContext, expected_policy_from_echo, render,
                                        render_quarantine)
from omarchy_wireguard.system import CommandRunner, HostSystem, SystemFailure


class FakeRunner:
    def __init__(self, responses):
        self.responses = responses
        self.calls = []

    def run(self, argv, *, stdin=None, timeout=10):
        self.calls.append((argv, stdin, timeout))
        key = tuple(argv)
        response = self.responses.get(key)
        if isinstance(response, Exception):
            raise response
        if response is None:
            raise AssertionError(f"unexpected command: {argv}")
        return response


def observed_policy(rules):
    chain = ""
    signed = []
    for line in rules.splitlines():
        if line.strip().startswith("chain "):
            chain = line.strip().split()[1]
        match = re.search(r'comment "(owg:[^"]+)"', line)
        if match:
            signed.append((chain, match.group(1)))
    objects = [
        {"metainfo": {"json_schema_version": 1}},
        {"table": {"family": "inet", "name": "omarchy_wireguard", "handle": 1}},
        {"chain": {"family": "inet", "table": "omarchy_wireguard", "name": "output",
                   "handle": 2, "type": "filter", "hook": "output", "prio": -10,
                   "policy": "drop"}},
        {"chain": {"family": "inet", "table": "omarchy_wireguard", "name": "forward",
                   "handle": 3, "type": "filter", "hook": "forward", "prio": -10,
                   "policy": "drop"}},
    ]
    objects.extend({"rule": {"family": "inet", "table": "omarchy_wireguard", "chain": chain,
                             "handle": index + 4, "comment": comment,
                             "expr": [{"counter": {"packets": 0, "bytes": 0}}]}}
                   for index, (chain, comment) in enumerate(signed))
    return json.dumps({"nftables": objects})


def echoed_policy(rules):
    observed = json.loads(observed_policy(rules))["nftables"]
    return json.dumps({"nftables": [
        {"add": entry} for entry in observed
        if next(iter(entry)) in {"table", "chain", "rule"}
    ]})


class SystemTests(unittest.TestCase):
    def test_quarantine_is_installed_without_host_discovery(self):
        class Runner:
            def __init__(self):
                self.calls = []

            def run(self, argv, *, stdin=None, timeout=10):
                self.calls.append((argv, stdin, timeout))
                if "--echo" in argv:
                    return echoed_policy(render_quarantine())
                if argv[:2] == ["nft", "-j"]:
                    return observed_policy(render_quarantine())
                return ""

        runner = Runner()
        HostSystem(runner).apply_quarantine()
        self.assertEqual(runner.calls[0][0], ["nft", "-j", "--echo", "-f", "-"])
        self.assertIn("policy drop", runner.calls[0][1])
        self.assertNotIn("ip -json", runner.calls[0][1])
        self.assertEqual(runner.calls[1][0],
                         ["nft", "-j", "list", "table", "inet", "omarchy_wireguard"])

    def test_firewall_apply_refuses_unverified_readback(self):
        class Runner:
            def run(self, argv, *, stdin=None, timeout=10):
                if "--echo" in argv:
                    return echoed_policy(render_quarantine())
                if argv[:2] == ["nft", "-j"]:
                    return json.dumps({"nftables": []})
                return ""

        with self.assertRaisesRegex(SystemFailure, "verification"):
            HostSystem(Runner()).apply_quarantine()

    def test_command_runner_never_uses_a_shell(self):
        completed = subprocess.CompletedProcess(["true"], 0, "ok\n", "")
        with patch("subprocess.run", return_value=completed) as run:
            self.assertEqual(CommandRunner().run(["true"]), "ok\n")
        _args, kwargs = run.call_args
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")

    def test_verification_requires_all_network_guarantees(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        context = FirewallContext(
            tunnel_interface="wg0", lan_prefixes=("192.168.1.0/24",),
            lan_resolvers=("192.168.1.1",), resolver_uid=992,
            physical_interfaces=("eth0",),
            lan_dns_links=(("eth0", ("192.168.1.1",)),),
            tunnel_dns=("10.0.0.1",))
        nft_key = ("nft", "-j", "list", "table", "inet", "omarchy_wireguard")
        responses = {
            ("nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", uuid): "activated\nwg0\n",
            ("wg", "show", "wg0", "fwmark"): "0x6f7467\n",
            ("ip", "-json", "route", "get", "1.1.1.1"): json.dumps([{"dev": "wg0"}]),
            ("ip", "-6", "-json", "route", "get", "2606:4700:4700::1111"):
                SystemFailure("no IPv6 route"),
            nft_key: observed_policy(render(context)),
            ("resolvectl", "dns", "wg0"): "Link 7 (wg0): 10.0.0.1\n",
            ("resolvectl", "domain", "wg0"): "Link 7 (wg0): ~.\n",
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): ~lan\n",
            ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1\n",
            ("resolvectl", "default-route", "eth0"): "Link 2 (eth0): no\n",
            ("wg", "show", "wg0", "latest-handshakes"): "peer\t950\n",
        }
        def verify():
            system = HostSystem(FakeRunner(responses))
            system.expected_firewall = expected_policy_from_echo(echoed_policy(render(context)))
            return system.verify(uuid, "wg0", now=1000, firewall_context=context)

        result = verify()
        self.assertTrue(result.ok)
        self.assertTrue(all(result.checks.values()))

        responses[("wg", "show", "wg0", "latest-handshakes")] = "peer\t800\n"
        result = verify()
        self.assertFalse(result.ok)
        self.assertFalse(result.checks["handshake_fresh"])

        responses[("ip", "-json", "route", "get", "1.1.1.1")] = json.dumps([{"dev": "eth0"}])
        result = verify()
        self.assertFalse(result.checks["ipv4_default"])

        responses[("wg", "show", "wg0", "fwmark")] = "0x0\n"
        result = verify()
        self.assertFalse(result.checks["wireguard_fwmark"])

        responses[nft_key] = json.dumps({"nftables": []})
        result = verify()
        self.assertFalse(result.checks["firewall_policy"])

        responses[nft_key] = observed_policy(render(context))
        responses[("resolvectl", "domain", "eth0")] = "Link 2 (eth0): ~. ~lan\n"
        result = verify()
        self.assertFalse(result.checks["split_dns"])

        responses[("resolvectl", "domain", "eth0")] = "Link 2 (eth0): ~lan\n"
        responses[("resolvectl", "dns", "eth0")] = "Link 2 (eth0): 192.168.1.1 192.168.1.2\n"
        result = verify()
        self.assertFalse(result.checks["split_dns"])

    def test_only_prefixed_profiles_are_managed(self):
        runner = FakeRunner({
            ("nmcli", "-t", "-f", "NAME,UUID", "connection", "show"):
                "omarchy-wireguard-japan:managed-uuid\nwork-vpn:unrelated-uuid\n",
        })
        self.assertEqual(HostSystem(runner).managed_profiles(),
                         {"managed-uuid": "omarchy-wireguard-japan"})

    def test_remove_firewall_is_idempotent_and_scoped(self):
        absent = FakeRunner({("nft", "list", "tables"): "table inet filter\n"})
        HostSystem(absent).remove_firewall()
        self.assertEqual(len(absent.calls), 1)
        present = FakeRunner({
            ("nft", "list", "tables"): "table inet filter\ntable inet omarchy_wireguard\n",
            ("nft", "delete", "table", "inet", "omarchy_wireguard"): "",
        })
        HostSystem(present).remove_firewall()
        self.assertEqual(present.calls[-1][0], ["nft", "delete", "table", "inet", "omarchy_wireguard"])

    def test_configures_lan_split_dns_and_discovers_resolvers(self):
        runner = FakeRunner({
            ("resolvectl", "domain", "eth0", "~lan"): "",
            ("resolvectl", "default-route", "eth0", "no"): "",
            ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1 2001:db8::53\n",
        })
        context = HostSystem(runner).configure_lan_dns(FirewallContext(physical_interfaces=("eth0",)))
        self.assertEqual(set(context.lan_resolvers), {"192.168.1.1", "2001:db8::53"})
        self.assertEqual(context.lan_dns_links,
                          (("eth0", ("192.168.1.1", "2001:db8::53")),))

    def test_captures_and_restores_physical_dns_for_direct_mode(self):
        runner = FakeRunner({
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): corp.example ~.\n",
            ("resolvectl", "default-route", "eth0"): "Link 2 (eth0): yes\n",
            ("ip", "-json", "link", "show"): json.dumps([{"ifname": "eth0"}]),
            ("resolvectl", "domain", "eth0", "corp.example", "~."): "",
            ("resolvectl", "default-route", "eth0", "yes"): "",
        })
        system = HostSystem(runner)
        state = system.capture_lan_dns(("eth0",))
        self.assertEqual(state, (("eth0", ("corp.example", "~."), True),))
        system.restore_lan_dns(state)
        self.assertEqual(runner.calls[-2][0],
                         ["resolvectl", "domain", "eth0", "corp.example", "~."])
        self.assertEqual(runner.calls[-1][0],
                         ["resolvectl", "default-route", "eth0", "yes"])

    def test_tunnel_dns_requests_unescaped_ipv6_from_nmcli(self):
        class NmcliEscapingRunner:
            def __init__(self):
                self.writes = []

            def run(self, argv, **kwargs):
                if argv[0] == 'nmcli':
                    if 'ipv4.dns' in argv:
                        return '192.0.2.53\n'
                    address = '2001:db8::53'
                    if argv[1:3] != ['--escape', 'no']:
                        address = address.replace(':', '\\:')
                    return address + '\n'
                self.writes.append(argv)
                return ''

        runner = NmcliEscapingRunner()
        self.assertEqual(HostSystem(runner).configure_tunnel_dns(
                         '00000000-0000-0000-0000-000000000001', 'owg-test'),
                         ('192.0.2.53', '2001:db8::53'))
        self.assertEqual(runner.writes[0],
                         ['resolvectl', 'dns', 'owg-test', '192.0.2.53', '2001:db8::53'])

    def test_configures_tunnel_dns_from_nm_profile_with_fixed_order(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        runner = FakeRunner({
            ("nmcli", "--escape", "no", "-g", "ipv4.dns", "connection", "show", "uuid", uuid):
                "1.1.1.1, 9.9.9.9\n",
            ("nmcli", "--escape", "no", "-g", "ipv6.dns", "connection", "show", "uuid", uuid):
                "2606:4700:4700::1111\n",
            ("resolvectl", "dns", "owg-test", "1.1.1.1", "2606:4700:4700::1111", "9.9.9.9"): "",
            ("resolvectl", "domain", "owg-test", "~."): "",
            ("resolvectl", "default-route", "owg-test", "yes"): "",
        })
        servers = HostSystem(runner).configure_tunnel_dns(uuid, "owg-test")
        self.assertEqual(servers, ("1.1.1.1", "2606:4700:4700::1111", "9.9.9.9"))
        self.assertEqual([call[0][0] for call in runner.calls],
                         ["nmcli", "nmcli", "resolvectl", "resolvectl", "resolvectl"])
        self.assertEqual(runner.calls[2][0][:3], ["resolvectl", "dns", "owg-test"])

    def test_rejects_invalid_or_missing_profile_dns_before_resolved_changes(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        for ipv4 in ("", "1.1.1.1;evil"):
            runner = FakeRunner({
                ("nmcli", "--escape", "no", "-g", "ipv4.dns", "connection", "show", "uuid", uuid): ipv4,
                ("nmcli", "--escape", "no", "-g", "ipv6.dns", "connection", "show", "uuid", uuid): "",
            })
            with self.assertRaises(SystemFailure):
                HostSystem(runner).configure_tunnel_dns(uuid, "owg-test")
            self.assertTrue(all(call[0][0] == "nmcli" for call in runner.calls))

    def test_clears_only_tunnel_runtime_dns(self):
        runner = FakeRunner({("resolvectl", "revert", "owg-test"): ""})
        HostSystem(runner).clear_tunnel_dns("owg-test")
        self.assertEqual(runner.calls[0][0], ["resolvectl", "revert", "owg-test"])

    def test_inspects_physical_lan_and_bridge_ports(self):
        runner = FakeRunner({
            ("ip", "-json", "route", "show", "table", "main"): json.dumps([
                {"dst": "default", "dev": "eth0"},
                {"dst": "192.168.1.0/24", "dev": "eth0", "scope": "link"},
                {"dst": "0.0.0.0/1", "dev": "eth0", "scope": "link"},
                {"dst": "128.0.0.0/1", "dev": "eth0", "scope": "link"},
                {"dst": "10.8.0.0/24", "dev": "wg-work", "scope": "link"},
                {"dst": "172.17.0.0/16", "dev": "docker0", "scope": "link"},
                {"dst": "10.20.0.0/16", "dev": "alfred-vpn", "scope": "link"},
                {"dst": "default", "dev": "wg-work", "metric": 10},
                {"dst": "100.64.0.0/10", "dev": "tun0", "scope": "link"},
                {"dst": "default", "dev": "tun0", "metric": 20},
            ]),
            ("ip", "-6", "-json", "route", "show", "table", "main"): "[]",
            ("ip", "-json", "link", "show"): json.dumps([
                {"ifindex": 10, "ifname": "docker0", "linkinfo": {"info_kind": "bridge"}},
                {"ifindex": 11, "ifname": "veth123", "master": "docker0"},
                {"ifindex": 2, "ifname": "eth0", "linkinfo": {"info_kind": "ether"}},
                {"ifindex": 20, "ifname": "wg-work", "linkinfo": {"info_kind": "wireguard"}},
                {"ifindex": 21, "ifname": "alfred-vpn", "linkinfo": {"info_kind": "wireguard"}},
                {"ifindex": 22, "ifname": "tun0", "linkinfo": {"info_kind": "tun"}},
            ]),
            ("ip", "-json", "address", "show"): json.dumps([
                {"ifname": "eth0", "addr_info": [
                    {"family": "inet", "local": "192.168.1.23", "prefixlen": 24},
                    {"family": "inet6", "local": "fe80::23", "prefixlen": 64},
                ]},
                {"ifname": "wg-work", "addr_info": [
                    {"family": "inet", "local": "10.8.0.2", "prefixlen": 24},
                ]},
            ]),
        })
        context = HostSystem(runner).inspect_firewall_context()
        self.assertEqual(context.lan_prefixes, ("192.168.1.0/24", "fe80::/64"))
        self.assertEqual(context.physical_interfaces, ("eth0",))
        self.assertEqual(set(context.local_interfaces), {"docker0", "veth123"})

    def test_lan_prefixes_come_from_private_underlay_addresses_not_routes(self):
        runner = FakeRunner({
            ("ip", "-json", "route", "show", "table", "main"): json.dumps([
                {"dst": "default", "dev": "eth0"},
                {"dst": "0.0.0.0/1", "dev": "eth0", "scope": "link"},
                {"dst": "128.0.0.0/1", "dev": "eth0", "scope": "link"},
                {"dst": "203.0.113.0/24", "dev": "eth0", "scope": "link"},
            ]),
            ("ip", "-6", "-json", "route", "show", "table", "main"): json.dumps([
                {"dst": "::/1", "dev": "eth0", "scope": "link"},
                {"dst": "8000::/1", "dev": "eth0", "scope": "link"},
            ]),
            ("ip", "-json", "link", "show"): json.dumps([
                {"ifindex": 2, "ifname": "eth0", "linkinfo": {"info_kind": "ether"}},
            ]),
            ("ip", "-json", "address", "show"): json.dumps([
                {"ifname": "eth0", "addr_info": [
                    {"family": "inet", "local": "10.42.0.7", "prefixlen": 24},
                    {"family": "inet6", "local": "fd42::7", "prefixlen": 64},
                    {"family": "inet", "local": "203.0.113.7", "prefixlen": 24},
                ]},
            ]),
        })
        context = HostSystem(runner).inspect_firewall_context()
        self.assertEqual(context.lan_prefixes, ("10.42.0.0/24", "fd42::/64"))

    def test_import_sets_deterministic_interface_dns_and_permissions(self):
        from test_atomic_import import profile, Runner, NAME, UUID
        from omarchy_wireguard.system import _profile_keyfile
        runner = Runner()
        captured = []
        def publish(text):
            captured.append(text)
            runner.present = True
        with patch('omarchy_wireguard.system.uuid_module.uuid4', return_value=UUID), \
                patch('omarchy_wireguard.system.publish_keyfile', side_effect=publish):
            HostSystem(runner, controller_uid=os.getuid()).import_profile(profile(), NAME)
        expected = _profile_keyfile(profile(), NAME, UUID, os.getuid())
        self.assertEqual(captured, [expected])
        self.assertIn('autoconnect=false', expected)
        self.assertIn('permissions=user:' + pwd.getpwuid(os.getuid()).pw_name + ':;', expected)
        self.assertFalse(any('modify' in call for call in runner.calls))

    def test_activation_reasserts_positive_tunnel_dns_before_up(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        modify = ("nmcli", "connection", "modify", "uuid", uuid,
                  "wireguard.fwmark", "0x6f7467",
                  "ipv4.dns-priority", "10", "ipv4.dns-search", "~.")
        class ActivationRunner:
            def __init__(self):
                self.calls = []

            def run(self, argv, *, stdin=None, timeout=10):
                self.calls.append((argv, stdin, timeout))
                if argv[:4] == ["nmcli", "--wait", argv[2], "connection"]:
                    return ""
                if argv[:4] == ["nmcli", "-g", "GENERAL.DEVICES", "connection"]:
                    return "owg-test\n"
                if tuple(argv) == modify:
                    return ""
                raise AssertionError(f"unexpected command: {argv}")

        runner = ActivationRunner()
        self.assertEqual(HostSystem(runner).activate(uuid, 10), "owg-test")
        self.assertEqual(tuple(runner.calls[0][0]), modify)
        self.assertEqual(runner.calls[1][0][0:2], ["nmcli", "--wait"])
        self.assertEqual(runner.calls[1][0][3:], ["connection", "up", "uuid", uuid])


if __name__ == "__main__":
    unittest.main()
