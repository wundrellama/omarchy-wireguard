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

if __name__ == '__main__': unittest.main()
