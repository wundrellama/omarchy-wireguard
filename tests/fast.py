"""Portable fast checks. Never starts the desktop, backend, or network services."""
import argparse
import ctypes
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
SUITES = ('backend', 'cli', 'install', 'integration', 'plugin')


def suite(name):
    # Execute each suite in a fresh interpreter: several fixtures share module names.
    sys.path.insert(0, str(ROOT / 'backend'))
    tests = unittest.defaultTestLoader.discover(str(ROOT / 'tests' / name), pattern='test_*.py')
    result = unittest.TextTestRunner(verbosity=2).run(tests)
    if not result.testsRun or result.skipped:
        print('Fast checks require nonempty suites without skipped tests.', file=sys.stderr)
        return 1
    return 0 if result.wasSuccessful() else 1


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--suite', choices=SUITES, help=argparse.SUPPRESS)
    parser.add_argument('--output', type=Path, help='Directory for logs and summary.json')
    args = parser.parse_args()
    if args.suite:
        return suite(args.suite)

    # The real libnm test only parses synthetic keyfiles, without a daemon or bus.
    try:
        for library in ('libnm.so.0', 'libglib-2.0.so.0', 'libgobject-2.0.so.0'):
            ctypes.CDLL(library)
    except OSError:
        print('Missing libnm/GLib runtime libraries. Install libnm0 on Ubuntu or libnm on Arch.', file=sys.stderr)
        return 1

    output = args.output or Path(tempfile.mkdtemp(prefix='wireguard-fast-'))
    output.mkdir(parents=True, exist_ok=True)
    env = {**os.environ, 'PYTHONDONTWRITEBYTECODE': '1', 'PYTHONPATH': str(ROOT / 'backend')}
    checks = [(name, [sys.executable, '-B', str(Path(__file__).resolve()), '--suite', name]) for name in SUITES]
    checks.append(('node-tests', ['node', '--test', *map(str, sorted((ROOT / 'tests/plugin').glob('*.test.js')))]))
    checks.append(('shell-syntax', ['/bin/bash', '-n', str(ROOT / 'tests/fast')]))
    for script in sorted((ROOT / 'scripts').iterdir()):
        if script.is_file():
            checks.append(('syntax-' + script.name, ['/bin/bash', '-n', str(script)]))
    for script in sorted((ROOT / 'plugin').glob('*.js')):
        checks.append(('syntax-' + script.name, ['node', '--check', str(script)]))

    results = []
    for name, command in checks:
        print('\n=== ' + name + ' ===', flush=True)
        try:
            result = subprocess.run(command, cwd=ROOT, env=env, text=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, timeout=90)
            text, code = result.stdout, result.returncode
        except (OSError, subprocess.TimeoutExpired) as exc:
            text, code = str(exc), 1
        (output / (name + '.log')).write_text(text)
        print(text, end='' if text.endswith('\n') else '\n', flush=True)
        results.append({'name': name, 'exit_code': code})

    # Compile source without writing __pycache__ or executing application code.
    try:
        sources = [ROOT / 'bin/omarchy-wireguard']
        for directory in ('backend', 'plugin', 'tests'):
            sources.extend(sorted((ROOT / directory).rglob('*.py')))
        for source in sources:
            compile(source.read_bytes(), str(source), 'exec')
        json.loads((ROOT / 'manifest.json').read_text())
        results.append({'name': 'python-json-syntax', 'exit_code': 0})
    except (SyntaxError, ValueError, OSError) as exc:
        (output / 'python-json-syntax.log').write_text(str(exc))
        print(exc, file=sys.stderr)
        results.append({'name': 'python-json-syntax', 'exit_code': 1})
    (output / 'summary.json').write_text(json.dumps(results, indent=2) + '\n')
    print('\nResults: ' + str(output))
    return 1 if any(item['exit_code'] for item in results) else 0


if __name__ == '__main__':
    sys.exit(main())
