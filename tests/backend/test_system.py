import json
import os
import pwd
import subprocess
import tempfile
import unittest
from unittest.mock import patch

from omarchy_wireguard.importer import Profile
from omarchy_wireguard.nftables import FirewallContext
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
            ("nft", "list", "table", "inet", "omarchy_wireguard"):
                "table inet omarchy_wireguard { chain output { type filter hook output priority -10; policy drop; meta mark 0x6f7467; comment \"WireGuard fail closed\"; } }",
            ("resolvectl", "dns", "wg0"): "Link 7 (wg0): 10.0.0.1\n",
            ("resolvectl", "domain", "wg0"): "Link 7 (wg0): ~.\n",
            ("resolvectl", "domain", "eth0"): "Link 2 (eth0): ~lan\n",
            ("resolvectl", "dns", "eth0"): "Link 2 (eth0): 192.168.1.1\n",
            ("resolvectl", "default-route", "eth0"): "Link 2 (eth0): no\n",
            ("wg", "show", "wg0", "latest-handshakes"): "peer\t950\n",
        }
        context = FirewallContext(physical_interfaces=("eth0",),
                                  lan_dns_links=(("eth0", ("192.168.1.1",)),),
                                  tunnel_dns=("10.0.0.1",))
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

        responses[("nft", "list", "table", "inet", "omarchy_wireguard")] = (
            "table inet omarchy_wireguard { chain output { type filter hook output priority -10; "
            "policy drop; comment \"WireGuard fail closed\"; } }")
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.checks["firewall_policy"])

        responses[("nft", "list", "table", "inet", "omarchy_wireguard")] = (
            "table inet omarchy_wireguard { chain output { type filter hook output priority -10; "
            "policy drop; meta mark 0x6f7467; comment \"WireGuard fail closed\"; } }")
        responses[("resolvectl", "domain", "eth0")] = "Link 2 (eth0): ~. ~lan\n"
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
        self.assertFalse(result.checks["split_dns"])

        responses[("resolvectl", "domain", "eth0")] = "Link 2 (eth0): ~lan\n"
        responses[("resolvectl", "dns", "eth0")] = "Link 2 (eth0): 192.168.1.1 192.168.1.2\n"
        result = HostSystem(FakeRunner(responses)).verify(uuid, "wg0", now=1000,
                                                          firewall_context=context)
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

    def test_configures_tunnel_dns_from_nm_profile_with_fixed_order(self):
        uuid = "00000000-0000-0000-0000-000000000001"
        runner = FakeRunner({
            ("nmcli", "-g", "ipv4.dns", "connection", "show", "uuid", uuid):
                "1.1.1.1, 9.9.9.9\n",
            ("nmcli", "-g", "ipv6.dns", "connection", "show", "uuid", uuid):
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
                ("nmcli", "-g", "ipv4.dns", "connection", "show", "uuid", uuid): ipv4,
                ("nmcli", "-g", "ipv6.dns", "connection", "show", "uuid", uuid): "",
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
        name = "omarchy-wireguard-japan-tokyo-1"
        import_command = ("nmcli", "connection", "import", "type", "wireguard", "file", path)
        runner = FakeRunner({import_command: f"Connection imported ({uuid})\n"})
        profile = Profile("jp.conf", "Japan", "Tokyo", "192.0.2.1", 51820,
                          "[Interface]\nPrivateKey = secret\n")
        with patch("omarchy_wireguard.system.tempfile.mkstemp", return_value=(fd, path)):
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
        self.assertEqual(modify[modify.index("wireguard.fwmark") + 1], "0x6f7467")
        self.assertNotIn("7304295", modify)
        self.assertIn("ipv4.dns-search", modify)
        self.assertIn("~.", modify)
        self.assertEqual(modify[modify.index("ipv4.dns-priority") + 1], "10")
        self.assertNotIn("ipv6.dns-priority", modify)
        self.assertNotIn("ipv6.dns-search", modify)
        self.assertNotIn("-100", modify)
        self.assertIn("user:" + pwd.getpwuid(os.getuid()).pw_name, modify)

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
