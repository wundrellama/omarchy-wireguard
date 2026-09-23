#!/usr/bin/env python3
"""Read-only host supervisor for isolated real NM/resolved lifecycle tests."""
import hashlib
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import tempfile

HERE = Path(__file__).resolve().parent
KINDS = ('user', 'mnt', 'pid', 'net', 'ipc', 'uts')


def host_state():
    return {key: json.loads(subprocess.check_output(['ip', '-j', *args], text=True, timeout=5))
            for key, args in {'links': ['link'], 'routes4': ['-4', 'route', 'show', 'table', 'all'],
                              'routes6': ['-6', 'route', 'show', 'table', 'all']}.items()}


def digest(obj):
    return hashlib.sha256(json.dumps(obj, sort_keys=True).encode()).hexdigest()


def main():
    scratch = Path(os.environ.get('TMPDIR', str(Path.home() / '.hermes/cache/scratch'))).resolve()
    assert scratch != Path('/tmp') and Path('/tmp') not in scratch.parents
    scratch.mkdir(parents=True, exist_ok=True)
    artifact = Path(tempfile.mkdtemp(prefix='wireguard-lifecycle-', dir=scratch))
    host = {k: os.readlink('/proc/self/ns/' + k) for k in KINDS}
    before = host_state()
    report = {'artifact_directory': str(artifact), 'host_namespaces': host,
              'kernel_release': os.uname().release,
              'host_before_sha256': digest(before), 'timeout_seconds': 120,
              'backend_sha256': {p.name: hashlib.sha256(p.read_bytes()).hexdigest()
                                 for p in (HERE.parents[1] / 'backend/omarchy_wireguard').glob('*.py')}}
    (artifact / 'host-before.json').write_text(json.dumps(before, indent=2) + '\n')
    args = ['--host', json.dumps(host)]
    refused = subprocess.run([sys.executable, '-B', str(HERE / 'sandbox.py'), *args],
                             text=True, capture_output=True, timeout=5)
    report['direct_host_invocation_refused'] = refused.returncode != 0 and 'REFUSED' in refused.stderr
    assert report['direct_host_invocation_refused'], 'guard self-test failed'
    command = ['bwrap', '--unshare-all', '--die-with-parent', '--new-session',
               '--uid', '0', '--gid', '0', '--cap-add', 'ALL', '--clearenv',
               '--setenv', 'PATH', '/usr/bin:/usr/sbin', '--setenv', 'LANG', 'C',
               '--setenv', 'HOME', '/root', '--setenv', 'TMPDIR', '/run',
               '--ro-bind', '/usr', '/usr', '--symlink', 'usr/bin', '/bin',
               '--symlink', 'usr/bin', '/sbin', '--symlink', 'usr/lib', '/lib',
               '--symlink', 'usr/lib', '/lib64', '--proc', '/proc', '--dev', '/dev',
               '--tmpfs', '/etc', '--tmpfs', '/run', '--tmpfs', '/var', '--tmpfs', '/sys',
               '--dir', '/root', '--dir', '/tmp',
               '--ro-bind', str(HERE), '/test',
               '--ro-bind', str(HERE.parents[1] / 'backend'), '/backend',
               '--chdir', '/', '/usr/bin/python', '-B', '/test/sandbox.py', *args]
    if '--inject-failure' in sys.argv:
        command.append('--inject-failure')
    if '--assert-import-inactive' in sys.argv:
        command.append('--assert-import-inactive')
    proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                            text=True, start_new_session=True)
    try:
        out, err = proc.communicate(timeout=120)
        report['exit_code'] = proc.returncode
        report['stderr'] = err
        try:
            report['result'] = json.loads(out)
        except ValueError:
            report['result'] = {'status': 'blocked', 'output': out}
    except subprocess.TimeoutExpired:
        report['result'] = {'status': 'blocked', 'error': '120 second bound exceeded'}
    finally:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        try:
            os.killpg(proc.pid, 0)
            report['supervisor_process_group_gone'] = False
        except ProcessLookupError:
            report['supervisor_process_group_gone'] = True
        after = host_state()
        report['host_after_sha256'] = digest(after)
        report['host_links_routes_unchanged'] = before == after
        report['host_namespaces_unchanged'] = host == {k: os.readlink('/proc/self/ns/' + k) for k in KINDS}
        (artifact / 'host-after.json').write_text(json.dumps(after, indent=2) + '\n')
    expected = 'expected_abort' if '--inject-failure' in sys.argv else 'passed'
    report['status'] = 'passed' if (report['result']['status'] == expected
        and report['host_links_routes_unchanged'] and report['host_namespaces_unchanged']
        and report['supervisor_process_group_gone'] and report['result'].get('children_reaped')) else 'failed_or_blocked'
    (artifact / 'results.json').write_text(json.dumps(report, indent=2) + '\n')
    print(json.dumps(report, indent=2))
    return 0 if report['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
