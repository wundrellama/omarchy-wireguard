"""Hostname bootstrap regression tests; no real host commands."""
import unittest
from omarchy_wireguard.nftables import FirewallContext
from omarchy_wireguard.system import HostSystem, SystemFailure
from test_system import FakeRunner
from test_controller import FakeSystem, MemoryStore, PROFILE, PROFILE_2
from omarchy_wireguard.controller import Controller
from dataclasses import replace
import json


class DnsRunner:
    def __init__(self):
        self.state = {i: (('original.test', '~.'), True) for i in ('eth0', 'wlan0')}
        self.calls = []
        self.fail = None
        self.missing = False

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if self.fail and self.fail(argv):
            raise SystemFailure('injected DNS command failure')
        if argv == ['ip', '-json', 'link', 'show']:
            return json.dumps([{'ifname': i} for i in self.state])
        _, operation, interface, *values = argv
        domains, default = self.state[interface]
        if operation == 'domain':
            if values:
                self.state[interface] = (tuple(values), default)
            return 'Link: ' + ' '.join(domains)
        if operation == 'default-route':
            if values:
                self.state[interface] = (domains, values[0] == 'yes')
            return 'Link: ' + ('yes' if default else 'no')
        if operation == 'dns':
            return 'Link: ' + ('' if self.missing else '192.0.2.53')
        raise AssertionError(argv)


class DnsSystem(FakeSystem):
    def __init__(self):
        super().__init__()
        self.runner = DnsRunner()
        real = HostSystem(self.runner)
        self.configure_lan_dns = real.configure_lan_dns
        self.capture_lan_dns = real.capture_lan_dns
        self.restore_lan_dns = real.restore_lan_dns
        self.hosts = []
        self.fail_resolve = False
        self.underlays = ('eth0', 'wlan0')

    def inspect_firewall_context(self, timeout=10):
        return replace(super().inspect_firewall_context(timeout), physical_interfaces=self.underlays)

    def resolve_endpoint(self, host, port, timeout=10):
        self.hosts.append(host)
        if not all(self.runner.state[i] == (('~lan', '~' + host), False)
                   for i in self.underlays):
            raise SystemFailure('no endpoint DNS route')
        if self.fail_resolve:
            raise SystemFailure('endpoint resolution failed')
        return (('192.0.2.4', port),)

    def activate(self, uuid, timeout):
        assert all(self.runner.state[i] == (('~lan', '~' + self.hosts[-1]), False)
                   for i in self.underlays), 'NM still needs bootstrap DNS'
        return super().activate(uuid, timeout)


class HostnameControllerTests(unittest.TestCase):
    def setUp(self):
        self.system = DnsSystem()
        self.store = MemoryStore({'profiles.json': [{**PROFILE, 'endpoint_host': 'vpn.example.test'}]})
        self.controller = Controller(self.store, self.system, sleeper=lambda _: None)

    def test_failures_strip_temporary_routes_before_retry_without_recapturing(self):
        for failure in ('resolution', 'activation', 'dns-query', 'partial-second-link'):
            with self.subTest(failure=failure):
                self.setUp()
                if failure == 'resolution':
                    self.system.fail_resolve = True
                elif failure == 'activation':
                    self.system.fail_activate = True
                elif failure == 'dns-query':
                    self.system.runner.fail = lambda argv: argv[:2] == ['resolvectl', 'dns']
                else:
                    self.system.runner.fail = lambda argv: argv == ['resolvectl', 'default-route', 'wlan0', 'no']
                    # Fail just the first write; cleanup must succeed on its own retry.
                    original = self.system.runner.fail
                    def once(argv):
                        if original(argv):
                            self.system.runner.fail = None
                            return True
                        return False
                    self.system.runner.fail = once
                self.controller.connect({'city': 'Japan/Tokyo'})
                self.controller.tick()
                self.assertEqual(self.controller.mode, 'failed')
                self.assertTrue(all(value == (('~lan',), False)
                                    for value in self.system.runner.state.values()))
                baseline = self.controller.dns_restore
                self.assertTrue(all(item[1] == ('original.test', '~.') for item in baseline))
                self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
                self.system.runner.fail = None
                self.system.fail_resolve = self.system.fail_activate = False
                self.controller.retry({}); self.controller.tick()
                self.assertEqual(self.controller.mode, 'connected')
                self.assertEqual(self.controller.dns_restore, baseline)

    def stage_bootstrap(self):
        self.controller.connect({'city': 'Japan/Tokyo'})
        self.controller._configure_lan_dns(self.system.inspect_firewall_context(), lambda: 10,
                                           'vpn.example.test')

    def test_restart_cleans_abandoned_routes_even_when_target_is_gone(self):
        self.stage_bootstrap()
        baseline = self.controller.dns_restore
        self.store.values['profiles.json'] = []
        restarted = Controller(self.store, self.system, sleeper=lambda _: None)
        restarted.boot()
        self.assertEqual(restarted.mode, 'failed')
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))
        self.assertEqual(restarted.dns_restore, baseline)

    def test_cleanup_failure_is_visible_and_blocks_failover_until_retried(self):
        self.controller.catalog.append({**PROFILE_2, 'endpoint_host': 'next.example.test'})
        self.system.fail_activate = True
        self.system.runner.fail = lambda argv: argv == ['resolvectl', 'domain', 'eth0', '~lan']
        self.controller.connect({'city': 'Japan/Tokyo'})
        with self.assertRaises(SystemFailure):
            self.controller.tick()
        self.assertEqual(self.controller.mode, 'failed')
        self.assertIn('bootstrap DNS cleanup', self.controller.last_error)
        self.assertTrue(self.controller.bootstrap_interfaces)
        self.assertEqual(self.system.activations, ['uuid-1'])
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
        self.assertEqual(self.system.removals, 0)
        self.system.runner.fail = None
        self.system.fail_activate = False
        self.controller.retry({}); self.controller.tick()
        self.assertEqual(self.controller.mode, 'connected')

    def test_cleanup_inspection_failure_reports_failed_and_retains_tracking(self):
        self.stage_bootstrap()
        baseline = self.controller.dns_restore
        inspect = self.system.inspect_firewall_context
        calls = 0

        def fail_cleanup_inspection(timeout=10):
            nonlocal calls
            calls += 1
            if calls > 1:
                raise SystemFailure('injected inspection failure')
            return inspect(timeout)

        self.system.inspect_firewall_context = fail_cleanup_inspection
        with self.assertRaises(SystemFailure):
            self.controller.emergency()
        self.assertEqual(self.controller.mode, 'failed')
        self.assertIn('bootstrap DNS cleanup', self.controller.last_error)
        self.assertIsNone(self.controller.retry_at)
        self.assertEqual(self.controller.bootstrap_interfaces, {'eth0', 'wlan0'})
        self.assertEqual(self.controller.dns_restore, baseline)
        self.assertIsNone(self.system.firewalls[-1].tunnel_interface)
        self.assertEqual(self.system.removals, 0)
        self.controller.tick()
        self.assertEqual(self.system.activations, [])
        self.system.inspect_firewall_context = inspect
        self.controller.emergency()
        self.assertFalse(self.controller.bootstrap_interfaces)
        self.assertTrue(all(value == (('~lan',), False)
                            for value in self.system.runner.state.values()))

    def test_missing_dns_stops_before_resolution_or_activation(self):
        self.system.runner.missing = True
        self.controller.connect({'city': 'Japan/Tokyo'}); self.controller.tick()
        self.assertEqual(self.controller.mode, 'failed')
        self.assertEqual(self.system.hosts, [])
        self.assertEqual(self.system.activations, [])
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))

    def test_invalid_target_hostname_has_no_connect_side_effects(self):
        self.controller.catalog[0]['endpoint_host'] = '~.'
        with self.assertRaises(SystemFailure):
            self.controller.connect({'city': 'Japan/Tokyo'})
        self.assertFalse(self.controller.enabled)
        self.assertEqual(self.system.runner.calls, [])
        self.assertEqual(self.system.firewalls, [])
        self.assertEqual(self.system.deactivations, 0)

    def test_emergency_strips_bootstrap_even_if_firewall_refresh_fails(self):
        self.stage_bootstrap()
        def fail(*args, **kwargs):
            raise SystemFailure('nft unavailable')
        self.system.apply_firewall = fail
        with self.assertRaises(SystemFailure):
            self.controller.emergency()
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))
        self.assertEqual(self.system.removals, 0)

    def test_disconnect_strips_bootstrap_even_if_nm_deactivation_fails(self):
        self.stage_bootstrap()
        self.system.fail_deactivate = True
        with self.assertRaises(SystemFailure):
            self.controller.disconnect({})
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))
        self.assertEqual(self.system.removals, 0)

    def test_failover_only_routes_next_hostname_and_preserves_baseline(self):
        self.controller.catalog.append({**PROFILE_2, 'endpoint_host': 'next.example.test'})
        self.system.fail_uuids = {'uuid-1'}
        self.controller.connect({'city': 'Japan/Tokyo'}); self.controller.tick()
        self.assertEqual(self.system.hosts, ['vpn.example.test', 'next.example.test'])
        self.assertEqual(self.controller.mode, 'connected')
        self.assertTrue(all(item[1] == ('original.test', '~.') for item in self.controller.dns_restore))
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))

    def test_departed_underlay_recovers_baseline_and_is_not_recaptured_dirty(self):
        self.stage_bootstrap()
        self.system.underlays = ('eth0',)
        self.controller.emergency()
        self.assertEqual(self.system.runner.state['wlan0'], (('original.test', '~.'), True))
        self.assertEqual(self.system.runner.state['eth0'], (('~lan',), False))
        self.controller.retry({}); self.controller.tick()
        self.assertEqual(self.controller.mode, 'connected')
        self.assertEqual(self.controller.dns_restore, (('eth0', ('original.test', '~.'), True),))

    def test_disabled_restart_restores_baseline_from_abandoned_bootstrap(self):
        self.stage_bootstrap()
        self.store.values['state.json'] = {'enabled': False, 'target': None, 'mru': []}
        Controller(self.store, self.system).boot()
        self.assertTrue(all(value == (('original.test', '~.'), True)
                            for value in self.system.runner.state.values()))
        self.assertEqual(self.store.values['dns.json'], [])

    def test_success_keeps_route_through_activation_then_strips_on_both_underlays(self):
        self.controller.connect({'city': 'Japan/Tokyo'})
        self.controller.tick()
        self.assertEqual(self.controller.mode, 'connected')
        self.assertEqual(self.system.hosts, ['vpn.example.test'])
        self.assertTrue(all(value == (('~lan',), False) for value in self.system.runner.state.values()))
        baseline = tuple((i, ('original.test', '~.'), True) for i in ('eth0', 'wlan0'))
        self.assertEqual(self.controller.dns_restore, baseline)
        self.controller.disconnect({})
        self.assertEqual(self.controller.dns_restore, ())
        self.assertTrue(all(value == (('original.test', '~.'), True)
                            for value in self.system.runner.state.values()))



class HostnameSystemTests(unittest.TestCase):
    def test_numeric_endpoints_do_not_add_routes(self):
        for host in ('192.0.2.1', '2001:db8::1', None):
            runner = FakeRunner({
                ('resolvectl', 'domain', 'eth0', '~lan'): '',
                ('resolvectl', 'default-route', 'eth0', 'no'): '',
                ('resolvectl', 'dns', 'eth0'): 'Link 2 (eth0): 192.0.2.53',
            })
            HostSystem(runner).configure_lan_dns(
                FirewallContext(physical_interfaces=('eth0',)), endpoint_host=host)
            self.assertEqual(len(runner.calls), 3)

    def test_invalid_hostname_rejected_before_any_commands(self):
        for host in ('', '.', '~.', '~example.test', 'com', 'lan', '-evil.test',
                     'evil-.test', 'evil..test', 'a.test ~.', 'a.test\n~.',
                     '*.test', 'bad_name.test', 'a/test', 'a:53', 'a.test.',
                     'é.test', 'a' * 64 + '.test', ('a.' * 127) + 'test'):
            with self.subTest(host=host):
                runner = FakeRunner({})
                with self.assertRaises(SystemFailure):
                    HostSystem(runner).configure_lan_dns(
                        FirewallContext(physical_interfaces=('eth0',)), endpoint_host=host)
                self.assertEqual(runner.calls, [])

    def test_bootstrap_route_is_full_hostname_and_normal_reassert_removes_it(self):
        runner = FakeRunner({
            ('resolvectl', 'domain', 'eth0', '~lan', '~vpn.example.test'): '',
            ('resolvectl', 'domain', 'eth0', '~lan'): '',
            ('resolvectl', 'default-route', 'eth0', 'no'): '',
            ('resolvectl', 'dns', 'eth0'): 'Link 2 (eth0): 192.0.2.53',
        })
        system = HostSystem(runner)
        base = FirewallContext(physical_interfaces=('eth0',))
        system.configure_lan_dns(base, endpoint_host='vpn.example.test')
        system.configure_lan_dns(base)
        self.assertEqual(runner.calls[0][0],
                         ['resolvectl', 'domain', 'eth0', '~lan', '~vpn.example.test'])
        self.assertEqual(runner.calls[3][0], ['resolvectl', 'domain', 'eth0', '~lan'])


if __name__ == '__main__':
    unittest.main()
