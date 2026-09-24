import importlib.util
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[2]

class TrafficTest(unittest.TestCase):
    def test_exact_mapping(self):
        path = ROOT / 'plugin/traffic.py'
        self.assertTrue(path.exists(), 'read-only traffic helper missing')
        spec = importlib.util.spec_from_file_location('traffic', path)
        assert spec and spec.loader
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        uuid = '4bd6ef4f-ca1a-4756-b9d2-55678bee6008'
        row = f'omarchy-wireguard-home:{uuid}:wireguard:owg-1234'
        self.assertEqual(m.parse_mapping(row, 'home'), (uuid, 'owg-1234'))
        self.assertIsNone(m.parse_mapping(row, 'other'))
        self.assertIsNone(m.parse_mapping(row+'\n'+row, 'home'))
        self.assertIsNone(m.parse_mapping(row.replace('owg-1234', '../net'), 'home'))
        self.assertIsNone(m.parse_mapping(row.replace('wireguard:owg', 'ethernet:owg'), 'home'))
        self.assertEqual(m.parse_mapping('unrelated\\:name:x:x:x\n'+row, 'home'), (uuid, 'owg-1234'))

    def test_sample_and_missing(self):
        import tempfile
        spec = importlib.util.spec_from_file_location('traffic', ROOT / 'plugin/traffic.py')
        assert spec and spec.loader
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        self.assertTrue(hasattr(m, 'sample'), 'sampling missing')
        row = 'omarchy-wireguard-home:4bd6ef4f-ca1a-4756-b9d2-55678bee6008:wireguard:owg-1234'
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); iface = root / 'owg-1234'; (iface / 'statistics').mkdir(parents=True)
            (iface/'ifindex').write_text('42\n')
            (iface/'statistics/rx_bytes').write_text('123456\n')
            (iface/'statistics/tx_bytes').write_text('500\n')
            result = m.sample('home', lambda: row, root)
            self.assertTrue(result['ok']); self.assertEqual(result['rx'], 123456)
            self.assertEqual(result['ifindex'], 42); self.assertGreater(result['time'], 0)
            self.assertFalse(m.sample('home', lambda: '', root)['ok'])
            rows = iter([row, row.replace('owg-1234', 'owg-other')])
            self.assertFalse(m.sample('home', lambda: next(rows), root)['ok'])
            def fail():
                raise OSError('unavailable')
            self.assertFalse(m.sample('home', fail, root)['ok'])
            (iface/'statistics/rx_bytes').write_text('invalid')
            self.assertFalse(m.sample('home', lambda: row, root)['ok'])
            (iface/'statistics/rx_bytes').unlink()
            self.assertFalse(m.sample('home', lambda: row, root)['ok'])
            self.assertFalse(m.sample('../home', lambda: row, root)['ok'])

class ProtonTrafficTest(unittest.TestCase):
    UUID = '4bd6ef4f-ca1a-4756-b9d2-55678bee6008'

    def module(self):
        spec = importlib.util.spec_from_file_location('traffic', ROOT / 'plugin/traffic.py')
        assert spec and spec.loader
        m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
        return m

    def test_exact_proton_mapping(self):
        m = self.module()
        self.assertTrue(hasattr(m, 'parse_proton_mapping'), 'Proton mapping mode missing')
        row = f'ProtonVPN CH#12:{self.UUID}:wireguard:proton0'
        wifi = f'Home Wi-Fi:{self.UUID}:802-11-wireless:wlan0'
        self.assertEqual(m.parse_proton_mapping(row + '\n' + wifi), (self.UUID, 'proton0'))
        self.assertEqual(m.parse_proton_mapping(r'ProtonVPN US-CA#148:' + self.UUID + ':wireguard:proton0'), (self.UUID, 'proton0'))
        self.assertIsNone(m.parse_proton_mapping(''))
        self.assertIsNone(m.parse_proton_mapping(wifi))
        self.assertIsNone(m.parse_proton_mapping(row + '\n' + row), 'duplicates rejected')
        self.assertIsNone(m.parse_proton_mapping(row.replace('wireguard', 'vpn')), 'wrong type rejected')
        self.assertIsNone(m.parse_proton_mapping(row.replace('proton0', 'proton1')), 'wrong device rejected')
        self.assertIsNone(m.parse_proton_mapping(row.replace('ProtonVPN ', 'Proton ')), 'name prefix required')
        self.assertIsNone(m.parse_proton_mapping(row.replace(self.UUID, 'not-a-uuid')))
        # No wildcard fallback: a managed WireGuard tunnel never maps as Proton.
        managed = f'omarchy-wireguard-home:{self.UUID}:wireguard:owg-1234'
        self.assertIsNone(m.parse_proton_mapping(managed))
        # A second connection claiming the Proton name or device is ambiguous.
        self.assertIsNone(m.parse_proton_mapping(row + f'\nProtonVPN IT#1:{self.UUID}:wireguard:owg-x'))
        self.assertIsNone(m.parse_proton_mapping(row + f'\nOther:{self.UUID}:wireguard:proton0'))
        # A malformed row mentioning Proton is ambiguous, never skipped.
        self.assertIsNone(m.parse_proton_mapping(row + f'\nProtonVPN IT#1:{self.UUID}:wireguard'), 'short Proton row')
        self.assertIsNone(m.parse_proton_mapping(row + f'\nOther:{self.UUID}:wireguard:proton0:extra'), 'long proton0 row')
        self.assertEqual(m.parse_proton_mapping(row + '\nWi-Fi:x:802-11-wireless'), (self.UUID, 'proton0'),
                         'unrelated malformed rows still ignored')
        # WireGuard mode never matches the Proton row.
        self.assertIsNone(m.parse_mapping(row, 'home'))
        self.assertIsNone(m.parse_mapping(row, 'proton'))

    def test_proton_sample(self):
        import tempfile
        m = self.module()
        row = f'ProtonVPN CH#12:{self.UUID}:wireguard:proton0'
        with tempfile.TemporaryDirectory() as d:
            root = Path(d); iface = root / 'proton0'; (iface / 'statistics').mkdir(parents=True)
            (iface/'ifindex').write_text('9\n')
            (iface/'statistics/rx_bytes').write_text('700\n')
            (iface/'statistics/tx_bytes').write_text('80\n')
            result = m.sample('@proton', lambda: row, root)
            self.assertTrue(result['ok'])
            self.assertEqual((result['profile'], result['interface'], result['uuid'], result['rx'], result['tx']),
                             ('@proton', 'proton0', self.UUID, 700, 80))
            self.assertFalse(m.sample('@proton', lambda: row + '\n' + row, root)['ok'])
            self.assertFalse(m.sample('@proton', lambda: '', root)['ok'])
            self.assertFalse(m.sample('@other', lambda: row, root)['ok'])
            self.assertFalse(m.sample('home', lambda: row, root)['ok'])


if __name__ == '__main__': unittest.main()
