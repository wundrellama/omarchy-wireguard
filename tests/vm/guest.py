#!/usr/bin/python3
"""Executed only inside the disposable guest by vm-proof.service."""
import hashlib
import json
import os
from pathlib import Path
import subprocess
import time

checks = []

def run(*args, ok=True):
    result = subprocess.run(args, text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=40)
    print('+', ' '.join(args), '\n', result.stdout, result.stderr, flush=True)
    if ok and result.returncode:
        raise RuntimeError(f'{args}: exit {result.returncode}')
    return result

def check(name, condition):
    if not condition:
        raise AssertionError(name)
    checks.append(name)
    print('VM_ASSERT_PASS ' + name, flush=True)

def nm_identity():
    return run('systemctl', 'show', 'NetworkManager.service', '-p', 'MainPID', '-p', 'InvocationID').stdout

def nm_preserved(stage):
    check(stage + ': NM active', run('systemctl', 'is-active', '--quiet', 'NetworkManager.service', ok=False).returncode == 0)
    check(stage + ': NM never restarted', nm_identity() == baseline)
    check(stage + ': unrelated profile unchanged', run('nmcli', '-g', 'connection.id,connection.uuid,connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.dns,ipv4.dns-search', 'connection', 'show', 'vm-unrelated').stdout == profile)
    check(stage + ': unrelated nft table retained', run('nft', 'list', 'table', 'inet', 'vm_unrelated', ok=False).returncode == 0)

def firewall_absent(stage):
    tables = json.loads(run('nft', '-j', 'list', 'tables').stdout)['nftables']
    check(stage + ': firewall absent', not any(x.get('table', {}).get('name') == 'omarchy_wireguard' for x in tables))

def wait_socket():
    for _ in range(60):
        if Path('/run/omarchy-wireguard/control.sock').is_socket():
            return
        time.sleep(.1)
    raise RuntimeError('daemon control socket never appeared')

try:
    check('actual systemd PID1', Path('/proc/1/comm').read_text().strip() == 'systemd')
    run('systemctl', '--version')
    for module in ('nf_tables', 'nft_ct', 'nft_fib_inet', 'wireguard', 'dummy'):
        run('modprobe', module)
    run('ip', 'link', 'set', 'lo', 'up')
    run('systemctl', 'start', 'dbus.service', 'systemd-resolved.service', 'NetworkManager.service')
    check('real resolved active', run('systemctl', 'is-active', '--quiet', 'systemd-resolved.service', ok=False).returncode == 0)
    run('resolvectl', 'status')
    run('nmcli', 'connection', 'add', 'type', 'dummy', 'ifname', 'vmunrelated', 'con-name', 'vm-unrelated', 'connection.autoconnect', 'no', 'ipv4.method', 'manual', 'ipv4.addresses', '192.0.2.9/24', 'ipv4.dns', '192.0.2.53', 'ipv4.dns-search', 'untouched.test', 'ipv6.method', 'disabled')
    run('nmcli', 'connection', 'up', 'vm-unrelated')
    run('ip', 'link', 'add', 'vmwg', 'type', 'wireguard')
    run('wg', 'show', 'vmwg')
    run('ip', 'link', 'del', 'vmwg')
    check('real WireGuard kernel interface exercised', True)
    run('nft', 'add', 'table', 'inet', 'vm_unrelated')
    baseline = nm_identity()
    profile = run('nmcli', '-g', 'connection.id,connection.uuid,connection.autoconnect,ipv4.method,ipv4.addresses,ipv4.dns,ipv4.dns-search', 'connection', 'show', 'vm-unrelated').stdout

    run('/bin/bash', '/repo/scripts/install-backend', 'vmuser')
    wait_socket()
    response = json.loads(run('runuser', '-u', 'vmuser', '--', '/usr/bin/omarchy-wireguard', 'status').stdout)
    check('installed daemon socket usable by controller', response['ok'] is True)
    check('real NM Requires edge attached', 'omarchy-wireguard-firewall.service' in run('systemctl', 'show', 'NetworkManager.service', '-p', 'Requires').stdout)
    nm_preserved('install')
    # Exercise the production firewall renderer and real nft, not an inert table.
    run('/usr/bin/env', 'PYTHONPATH=/usr/lib/omarchy-wireguard/backend', '/usr/bin/python3', '-c', 'from omarchy_wireguard.system import HostSystem; from omarchy_wireguard.nftables import FirewallContext; HostSystem().apply_firewall(FirewallContext())')
    check('real rendered firewall installed', run('nft', 'list', 'table', 'inet', 'omarchy_wireguard', ok=False).returncode == 0)
    response = json.loads(run('/usr/bin/omarchy-wireguard', 'emergency-disable').stdout)
    check('emergency response disabled', response['result']['mode'] == 'disabled')
    check('emergency keeps required firewall service active', run('systemctl', 'is-active', '--quiet', 'omarchy-wireguard-firewall.service', ok=False).returncode == 0)
    check('emergency stops daemon', run('systemctl', 'is-active', '--quiet', 'omarchy-wireguard.service', ok=False).returncode != 0)
    firewall_absent('emergency')
    nm_preserved('emergency')
    run('/bin/bash', '/repo/scripts/uninstall-backend', 'vmuser')
    check('uninstall removes NM dependency', 'omarchy-wireguard-firewall.service' not in run('systemctl', 'show', 'NetworkManager.service', '-p', 'Requires').stdout)
    check('uninstall stops firewall unit', run('systemctl', 'is-active', '--quiet', 'omarchy-wireguard-firewall.service', ok=False).returncode != 0)
    check('uninstall removes backend files', not Path('/usr/lib/omarchy-wireguard').exists())
    firewall_absent('uninstall')
    nm_preserved('uninstall')
    # Fault injection: real systemd executes an ExecStartPost which attaches the
    # actual Requires drop-in, reloads PID1, records that edge, then exits 23.
    # The '+' prefix exempts ONLY the injected process from daemon sandboxing,
    # so it can attach a systemd dependency. The normal daemon stays hardened.
    # No production script or systemctl/nft/NM command is replaced.
    fault = Path('/etc/systemd/system/omarchy-wireguard.service.d')
    fault.mkdir(parents=True)
    (fault / '90-vm-fault.conf').write_text('[Service]\nRestart=no\nExecStartPost=+/bin/bash /vm-fault.sh\n')
    result = run('/bin/bash', '/repo/scripts/install-backend', 'vmuser', ok=False)
    check('injected installer failure reported', result.returncode != 0)
    check('injection reached real cached Requires edge', 'omarchy-wireguard-firewall.service' in Path('/run/vm-fault-edge').read_text())
    check('rollback detaches NM Requires before stopping firewall', 'omarchy-wireguard-firewall.service' not in run('systemctl', 'show', 'NetworkManager.service', '-p', 'Requires').stdout)
    check('rollback stops firewall service', run('systemctl', 'is-active', '--quiet', 'omarchy-wireguard-firewall.service', ok=False).returncode != 0)
    check('rollback removes dependency file', not Path('/etc/systemd/system/NetworkManager.service.d/50-omarchy-wireguard.conf').exists())
    firewall_absent('rollback')
    nm_preserved('rollback')
    print('VM_RESULT ' + json.dumps({'ok': True, 'guest_exit': 0, 'assertions': checks}), flush=True)
except BaseException as exc:
    print('VM_RESULT ' + json.dumps({'ok': False, 'guest_exit': 1, 'assertions': checks, 'error': str(exc)}), flush=True)
    run('systemctl', '--no-pager', '--full', 'status', 'dbus.service', 'systemd-resolved.service', 'NetworkManager.service', 'omarchy-wireguard.service', 'omarchy-wireguard-firewall.service', ok=False)
    run('journalctl', '--no-pager', '-n', '80', ok=False)
    raise SystemExit(1)
