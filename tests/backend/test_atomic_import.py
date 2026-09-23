import base64
import configparser
import os
import unittest
from unittest.mock import patch

from omarchy_wireguard.importer import parse_config
from omarchy_wireguard.system import HostSystem, SystemFailure, _profile_keyfile

KEY = base64.b64encode(bytes([1]) * 32).decode()
PSK = base64.b64encode(bytes([2]) * 32).decode()
UUID = '00000000-0000-0000-0000-000000000001'
NAME = 'omarchy-wireguard-test'
CONFIG = f'''[Interface]
PrivateKey={KEY}
Address=10.77.0.2/24, 2001:db8::2/64, 10.78.0.2/32
DNS=10.77.0.1, 2001:db8::1
ListenPort=51821
MTU=1400
[Peer]
PublicKey={KEY}
PresharedKey={PSK}
Endpoint=[2001:db8::1]:51820
AllowedIPs=0.0.0.0/0, ::/0, 10.4.0.0/16
PersistentKeepalive=25
'''


def profile():
    return parse_config('test.conf', CONFIG)


class Runner:
    def __init__(self):
        self.calls = []
        self.existing = ''
        self.identity = NAME
        self.present = False

    def run(self, argv, **kwargs):
        self.calls.append(argv)
        if argv == ['nmcli', '-t', '-f', 'UUID', 'connection', 'show']:
            return self.existing
        if argv == ['nmcli', '-g', 'connection.id', 'connection', 'show', 'uuid', UUID]:
            if not self.present:
                raise SystemFailure('not found')
            return self.identity
        if argv == ['nmcli', 'connection', 'delete', 'uuid', UUID]:
            self.present = False
            return ''
        raise AssertionError(argv)


class AtomicImportTests(unittest.TestCase):
    def setUp(self):
        self.runner = Runner()
        self.uuid_patch = patch('omarchy_wireguard.system.uuid_module.uuid4', return_value=UUID)
        self.uuid_patch.start()
        self.addCleanup(self.uuid_patch.stop)

    def publish(self, text):
        self.text = text
        self.runner.present = True

    def test_every_setting_precedes_publication_and_no_secret_argv(self):
        with patch('omarchy_wireguard.system.publish_keyfile', side_effect=self.publish) as publish:
            self.assertEqual(HostSystem(self.runner, os.getuid()).import_profile(profile(), NAME), UUID)
        self.assertEqual(publish.call_count, 1)
        keyfile = configparser.ConfigParser(interpolation=None)
        keyfile.read_string(self.text)
        conn, wg, peer = keyfile['connection'], keyfile['wireguard'], keyfile['wireguard-peer.' + KEY]
        self.assertEqual(conn['id'], NAME)
        self.assertEqual(conn['uuid'], UUID)
        self.assertEqual(conn['autoconnect'], 'false')
        self.assertRegex(conn['interface-name'], r'^owg-[0-9a-f]{10}$')
        self.assertTrue(conn['permissions'].startswith('user:'))
        self.assertEqual(int(wg['fwmark']), 0x6f7467)
        self.assertEqual(wg['private-key'], KEY)
        self.assertEqual(wg['private-key-flags'], '0')
        self.assertEqual(wg['listen-port'], '51821')
        self.assertEqual(wg['mtu'], '1400')
        self.assertEqual(peer['preshared-key'], PSK)
        self.assertEqual(peer['preshared-key-flags'], '0')
        self.assertEqual(peer['endpoint'], '[2001:db8::1]:51820')
        self.assertEqual(peer['allowed-ips'], '0.0.0.0/0;::/0;10.4.0.0/16;')
        self.assertEqual(peer['persistent-keepalive'], '25')
        self.assertEqual(keyfile['ipv4']['address2'], '10.78.0.2/32')
        for version, addr, dns in [(4, '10.77.0.2/24', '10.77.0.1;'), (6, '2001:db8::2/64', '2001:db8::1;')]:
            ip = keyfile[f'ipv{version}']
            self.assertEqual(ip['method'], 'manual')
            self.assertEqual(ip['address1'], addr)
            self.assertEqual(ip['dns'], dns)
            self.assertEqual(ip['dns-search'], '~.;')
            self.assertEqual(ip['dns-priority'], '10')
        self.assertNotIn(KEY, repr(self.runner.calls))
        self.assertNotIn(PSK, repr(self.runner.calls))
        self.assertFalse(any('modify' in c or 'import' in c for c in self.runner.calls))

    def test_failed_reply_after_add_rolls_back_only_new_uuid(self):
        def fail(text):
            self.publish(text)
            raise ValueError('reply lost')
        with patch('omarchy_wireguard.system.publish_keyfile', side_effect=fail):
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(profile(), NAME)
        self.assertFalse(self.runner.present)
        self.assertEqual(self.runner.calls[-1], ['nmcli', 'connection', 'delete', 'uuid', UUID])

    def test_rejected_add_does_not_delete_anything(self):
        with patch('omarchy_wireguard.system.publish_keyfile', side_effect=ValueError('rejected')):
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(profile(), NAME)
        self.assertFalse(any('delete' in c for c in self.runner.calls))

    def test_existing_uuid_is_never_published_updated_or_deleted(self):
        self.runner.existing = UUID + '\n'
        with patch('omarchy_wireguard.system.publish_keyfile') as publish:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(profile(), NAME)
        publish.assert_not_called()
        self.assertEqual(len(self.runner.calls), 1)

    def test_identity_changed_does_not_delete_unrelated_profile(self):
        self.runner.identity = 'unrelated'
        with patch('omarchy_wireguard.system.publish_keyfile', side_effect=self.publish):
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(profile(), NAME)
        self.assertTrue(self.runner.present)
        self.assertFalse(any('delete' in c for c in self.runner.calls))

    def test_unknown_uid_never_publishes(self):
        with patch('omarchy_wireguard.system.pwd.getpwuid', side_effect=KeyError), patch('omarchy_wireguard.system.publish_keyfile') as publish:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner, 123).import_profile(profile(), NAME)
        publish.assert_not_called()

    def test_malformed_key_never_reaches_nm(self):
        malformed = parse_config('test.conf', CONFIG.replace(KEY, 'not-a-key'))
        with patch('omarchy_wireguard.system.publish_keyfile') as publish:
            with self.assertRaises(SystemFailure):
                HostSystem(self.runner).import_profile(malformed, NAME)
        publish.assert_not_called()

    def test_out_of_range_interface_numbers_never_publish(self):
        for field, original, maximum in [('ListenPort', 51821, 65535), ('MTU', 1400, 4294967295)]:
            for value in (-1, maximum + 1):
                with self.subTest(field=field, value=value):
                    invalid = parse_config('test.conf', CONFIG.replace(f'{field}={original}', f'{field}={value}'))
                    with patch('omarchy_wireguard.system.publish_keyfile') as publish:
                        with self.assertRaises(SystemFailure):
                            HostSystem(self.runner).import_profile(invalid, NAME)
                    publish.assert_not_called()

    def test_interface_numeric_boundaries_are_preserved(self):
        for field, target, original, maximum in [('ListenPort', 'listen-port', 51821, 65535), ('MTU', 'mtu', 1400, 4294967295)]:
            for value in (0, 1, maximum):
                with self.subTest(field=field, value=value):
                    valid = parse_config('test.conf', CONFIG.replace(f'{field}={original}', f'{field}={value}'))
                    text = _profile_keyfile(valid, NAME, UUID, None)
                    self.assertIn(f'\n{target}={value}\n', text)

    def test_direct_profile_out_of_range_keepalive_never_publishes(self):
        from dataclasses import replace
        for value in (-1, 65536):
            with self.subTest(value=value):
                invalid = replace(profile(), config=CONFIG.replace('PersistentKeepalive=25', f'PersistentKeepalive={value}'))
                with patch('omarchy_wireguard.system.publish_keyfile') as publish:
                    with self.assertRaises(SystemFailure):
                        HostSystem(self.runner).import_profile(invalid, NAME)
                publish.assert_not_called()

    def test_direct_profile_keepalive_boundaries_and_importer_default(self):
        from dataclasses import replace
        for value in (0, 1, 65535):
            with self.subTest(value=value):
                config = CONFIG.replace('PersistentKeepalive=25', f'PersistentKeepalive={value}')
                direct = replace(profile(), config=config)
                self.assertIn(f'\npersistent-keepalive={value}\n', _profile_keyfile(direct, NAME, UUID, None))
                imported = parse_config('test.conf', config)
                self.assertIn('\npersistent-keepalive=25\n', _profile_keyfile(imported, NAME, UUID, None))
        direct = replace(profile(), config=CONFIG.replace('PersistentKeepalive=25\n', ''))
        self.assertIn('\npersistent-keepalive=0\n', _profile_keyfile(direct, NAME, UUID, None))

    def test_offline_libnm_preserves_numeric_boundaries(self):
        import ctypes.util
        import json
        import subprocess
        import sys
        import textwrap
        from dataclasses import replace

        if not ctypes.util.find_library('nm'):
            self.skipTest('libnm is not installed')
        cases = []
        for port, mtu, keepalive in [(0, 0, 0), (1, 1, 1), (65535, 4294967295, 65535), (51821, 1400, 25)]:
            config = CONFIG.replace('ListenPort=51821', f'ListenPort={port}').replace('MTU=1400', f'MTU={mtu}').replace('PersistentKeepalive=25', f'PersistentKeepalive={keepalive}')
            text = _profile_keyfile(replace(profile(), config=config), NAME, UUID, None)
            cases.append([text, port, mtu, keepalive])
        # Only parse/verify/read getters: no client, system bus, or publication.
        script = textwrap.dedent('''
            import ctypes as C
            import json
            import sys
            p, s, i, u = C.c_void_p, C.c_char_p, C.c_int, C.c_uint
            glib = C.CDLL('libglib-2.0.so.0')
            obj = C.CDLL('libgobject-2.0.so.0')
            nm = C.CDLL('libnm.so.0')
            def bind(lib, name, result, *args):
                f = getattr(lib, name)
                f.restype, f.argtypes = result, args
                return f
            new = bind(glib, 'g_key_file_new', p)
            load = bind(glib, 'g_key_file_load_from_data', i, p, s, C.c_size_t, i, p)
            free = bind(glib, 'g_key_file_unref', None, p)
            unref = bind(obj, 'g_object_unref', None, p)
            read = bind(nm, 'nm_keyfile_read', p, p, s, u, p, p, p)
            verify = bind(nm, 'nm_connection_verify', i, p, p)
            secrets = bind(nm, 'nm_connection_verify_secrets', i, p, p)
            setting = bind(nm, 'nm_connection_get_setting_by_name', p, p, s)
            port_get = bind(nm, 'nm_setting_wireguard_get_listen_port', u, p)
            mtu_get = bind(nm, 'nm_setting_wireguard_get_mtu', u, p)
            peer_get = bind(nm, 'nm_setting_wireguard_get_peer', p, p, u)
            keepalive_get = bind(nm, 'nm_wireguard_peer_get_persistent_keepalive', C.c_uint16, p)
            for text, port, mtu, keepalive in json.load(sys.stdin):
                key, connection = new(), None
                try:
                    data = text.encode()
                    assert load(key, data, len(data), 0, None)
                    connection = read(key, b'/', 0, None, None, None)
                    assert connection and verify(connection, None) and secrets(connection, None)
                    wg = setting(connection, b'wireguard')
                    assert wg
                    peer = peer_get(wg, 0)
                    assert peer
                    assert port_get(wg) == port
                    assert mtu_get(wg) == mtu
                    assert keepalive_get(peer) == keepalive
                finally:
                    if connection:
                        unref(connection)
                    free(key)
        ''')
        result = subprocess.run([sys.executable, '-c', script], input=json.dumps(cases),
                                capture_output=True, text=True, timeout=15,
                                env={**os.environ, 'G_DEBUG': 'fatal-warnings'})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(result.stderr, '')

    def test_no_optional_fields_and_single_family(self):
        config = f'[Interface]\nPrivateKey={KEY}\nAddress=10.77.0.2/24\nDNS=10.77.0.1\n[Peer]\nPublicKey={KEY}\nAllowedIPs=0.0.0.0/0\nEndpoint=vpn.example.test:1234\n'
        text = _profile_keyfile(parse_config('test.conf', config), NAME, UUID, None)
        self.assertIn('method=disabled', text)
        self.assertIn('permissions=\n', text)
        self.assertIn('endpoint=vpn.example.test:1234', text)
        self.assertNotIn('preshared-key=', text)
        self.assertNotIn('listen-port=', text)
        self.assertNotIn('mtu=', text)
