import json
import os
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from omarchy_torguard.importer import Profile
from omarchy_torguard.nftables import FirewallContext
from omarchy_torguard.system import CommandRunner, HostSystem, SystemFailure


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


class SystemTests(unittest.TestCase):
    def test_command_runner_never_uses_a_shell(self):
        completed = subprocess.CompletedProcess(["true"], 0, "ok\n", "")
        with patch("subprocess.run", return_value=completed) as run:
            self.assertEqual(CommandRunner().run(["true"]), "ok\n")
        _args, kwargs = run.call_args
        self.assertNotIn("shell", kwargs)
        self.assertEqual(kwargs["env"]["PATH"], "/usr/sbin:/usr/bin:/sbin:/bin")

    def test_verification_requires_all_network_guarantees(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        responses = {
            ("nmcli", "-g", "GENERAL.STATE,GENERAL.DEVICES", "connection", "show", "uuid", uuid): "activated\nwg0\n",
            ("wg", "show", "wg0", "fwmark"): "0x6f7467\n",
            ("ip", "-json", "route", "get", "1.1.1.1"): json.dumps([{"dev": "wg0"}]),
            ("ip", "-6", "-json", "route", "get", "2606:4700:4700::1111"):
                SystemFailure("no IPv6 route"),
            ("nft", "list", "table", "inet", "omarchy_torguard"):
                "table inet omarchy_torguard { chain output { type filter hook output priority -10; policy drop; meta mark 0x6f7467; comment \"TorGuard fail closed\"; } }",
            ("resolvectl", "status", "wg0"): "DNS Servers: 10.0.0.1\nDNS Domain: ~.\n",
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): corp.example ~lan\n",
            ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1\n",
            ("wg", "show", "wg0", "latest-handshakes"): "peer\t950\n",
        }
        context = FirewallContext(physical_interfaces=("eth0",),
                                  lan_dns_links=(("eth0", ("192.168.1.1",)),))
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertTrue(result.ok)
        self.assertTrue(all(result.checks.values()))

        responses[("wg", "show", "wg0", "latest-handshakes")] = "peer\t800\n"
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.ok)
        self.assertFalse(result.checks["handshake_fresh"])

        responses[("ip", "-json", "route", "get", "1.1.1.1")] = json.dumps([{"dev": "eth0"}])
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.checks["ipv4_default"])

        responses[("wg", "show", "wg0", "fwmark")] = "0x0\n"
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.checks["wireguard_fwmark"])

        responses[("nft", "list", "table", "inet", "omarchy_torguard")] = (
            "table inet omarchy_torguard { chain output { type filter hook output priority -10; "
            "policy drop; comment \"TorGuard fail closed\"; } }")
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.checks["firewall_policy"])

    def test_only_prefixed_profiles_are_managed(self):
        runner = FakeRunner({
            ("nmcli", "-t", "-f", "NAME,UUID", "connection", "show"):
                "omarchy-torguard-japan:managed-uuid\nwork-vpn:unrelated-uuid\n",
        })
        self.assertEqual(HostSystem(runner).managed_profiles(),
                         {"managed-uuid": "omarchy-torguard-japan"})

    def test_remove_firewall_is_idempotent_and_scoped(self):
        absent = FakeRunner({("nft", "list", "tables"): "table inet filter\n"})
        HostSystem(absent).remove_firewall()
        self.assertEqual(len(absent.calls), 1)
        present = FakeRunner({
            ("nft", "list", "tables"): "table inet filter\ntable inet omarchy_torguard\n",
            ("nft", "delete", "table", "inet", "omarchy_torguard"): "",
        })
        HostSystem(present).remove_firewall()
        self.assertEqual(present.calls[-1][0], ["nft", "delete", "table", "inet", "omarchy_torguard"])

    def test_configures_lan_split_dns_and_discovers_resolvers(self):
        runner = FakeRunner({
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): corp.example ~corp\n",
            ("resolvectl", "domain", "eth0", "corp.example", "~corp", "~lan"): "",
            ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1 2001:db8::53\n",
        })
        context = HostSystem(runner).configure_lan_dns(FirewallContext(physical_interfaces=("eth0",)))
        self.assertEqual(set(context.lan_resolvers), {"192.168.1.1", "2001:db8::53"})
        self.assertEqual(context.lan_dns_links,
                         (("eth0", ("192.168.1.1", "2001:db8::53")),))

    def test_restores_physical_dns_for_direct_mode(self):
        runner = FakeRunner({
            ("ip", "-json", "route", "show", "table", "main"):
                json.dumps([{"dst": "default", "dev": "eth0"}]),
            ("ip", "-6", "-json", "route", "show", "table", "main"): "[]",
            ("ip", "-json", "link", "show"): json.dumps([
                {"ifindex": 2, "ifname": "eth0", "linkinfo": {"info_kind": "ether"}},
            ]),
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): corp.example ~lan ~corp\n",
            ("resolvectl", "domain", "eth0", "corp.example", "~corp"): "",
        })
        HostSystem(runner).restore_lan_dns()
        self.assertEqual(runner.calls[-1][0],
                         ["resolvectl", "domain", "eth0", "corp.example", "~corp"])

    def test_inspects_physical_lan_and_bridge_ports(self):
        runner = FakeRunner({
            ("ip", "-json", "route", "show", "table", "main"): json.dumps([
                {"dst": "default", "dev": "eth0"},
                {"dst": "192.168.1.0/24", "dev": "eth0", "scope": "link"},
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
        })
        context = HostSystem(runner).inspect_firewall_context()
        self.assertEqual(context.lan_prefixes, ("192.168.1.0/24",))
        self.assertEqual(context.physical_interfaces, ("eth0",))
        self.assertEqual(set(context.local_interfaces), {"docker0", "veth123"})

    def test_import_sets_deterministic_interface_dns_and_permissions(self):
        fd, path = tempfile.mkstemp()
        uuid = "00000000-0000-0000-0000-000000000001"
        name = "omarchy-torguard-japan-tokyo-1"
        import_command = ("nmcli", "connection", "import", "type", "wireguard", "file", path)
        runner = FakeRunner({import_command: f"Connection imported ({uuid})\n"})
        profile = Profile("jp.conf", "Japan", "Tokyo", "192.0.2.1", 51820,
                          "[Interface]\nPrivateKey = secret\n")
        with patch("omarchy_torguard.system.tempfile.mkstemp", return_value=(fd, path)):
            # Accept the deterministic modify command after observing it.
            original = runner.run
            def run(argv, *, stdin=None, timeout=10):
                if argv[:5] == ["nmcli", "connection", "modify", "uuid", uuid]:
                    runner.calls.append((argv, stdin, timeout))
                    return ""
                return original(argv, stdin=stdin, timeout=timeout)
            runner.run = run
            HostSystem(runner, controller_uid=os.getuid()).import_profile(profile, name)
        modify = runner.calls[-1][0]
        self.assertIn("connection.interface-name", modify)
        self.assertIn("wireguard.fwmark", modify)
        self.assertIn(str(0x6F7467), modify)
        self.assertIn("ipv4.dns-search", modify)
        self.assertIn("~.", modify)
        self.assertEqual(modify[modify.index("ipv4.dns-priority") + 1], "10")
        self.assertEqual(modify[modify.index("ipv6.dns-priority") + 1], "10")
        self.assertNotIn("-100", modify)
        self.assertIn("user:" + pwd.getpwuid(os.getuid()).pw_name, modify)

    def test_activation_reasserts_positive_tunnel_dns_before_up(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        modify = ("nmcli", "connection", "modify", "uuid", uuid,
                  "wireguard.fwmark", str(0x6F7467),
                  "ipv4.dns-priority", "10", "ipv6.dns-priority", "10",
                  "ipv4.dns-search", "~.", "ipv6.dns-search", "~.")
        class ActivationRunner:
            def __init__(self):
                self.calls = []

            def run(self, argv, *, stdin=None, timeout=10):
                self.calls.append((argv, stdin, timeout))
                if argv[:4] == ["nmcli", "--wait", argv[2], "connection"]:
                    return ""
                if argv[:4] == ["nmcli", "-g", "GENERAL.DEVICES", "connection"]:
                    return "otg-test\n"
                if tuple(argv) == modify:
                    return ""
                raise AssertionError(f"unexpected command: {argv}")

        runner = ActivationRunner()
        self.assertEqual(HostSystem(runner).activate(uuid, 10), "otg-test")
        self.assertEqual(tuple(runner.calls[0][0]), modify)
        self.assertEqual(runner.calls[1][0][0:2], ["nmcli", "--wait"])
        self.assertEqual(runner.calls[1][0][3:], ["connection", "up", "uuid", uuid])


if __name__ == "__main__":
    unittest.main()
