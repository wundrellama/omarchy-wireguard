#!/usr/bin/env python3
"""Only starts real services after rejecting host namespaces and control paths."""
import argparse
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import selectors
import socket

sys.path.insert(0, '/backend')

HOST = {}
CURRENT = {}
CHECKS = []
CHILDREN = []
ENV = {'PATH': '/usr/bin:/usr/sbin', 'LANG': 'C', 'HOME': '/root', 'TMPDIR': '/run'}


def guard():
    if not HOST or any(os.readlink('/proc/self/ns/' + k) == v for k, v in HOST.items()):
        raise RuntimeError('REFUSED: host or incomplete namespace isolation')
    if CURRENT and any(os.readlink('/proc/self/ns/' + k) != v for k, v in CURRENT.items()):
        raise RuntimeError('REFUSED: namespace changed')
    if os.geteuid() != 0 or Path('/home/michael').exists() or Path('/run/host').exists():
        raise RuntimeError('REFUSED: unexpected root or host mount')
    # Require independent writable tmpfs mounts, not a writable host bind.
    mounts = {}
    for line in Path('/proc/self/mountinfo').read_text().splitlines():
        before, after = line.split(' - ', 1)
        fields = before.split()
        mounts[fields[4]] = (fields[5], after.split()[0])
    for path in ('/etc', '/run', '/var'):
        if mounts.get(path, ('', ''))[1] != 'tmpfs':
            raise RuntimeError('REFUSED: mutable path not isolated tmpfs: ' + path)
    if 'ro' not in mounts.get('/usr', ('', ''))[0].split(','):
        raise RuntimeError('REFUSED: /usr not read-only')


def cmd(argv, stdin=None, timeout=8):
    guard()
    assert argv[0] in {'mount', 'ip', 'wg', 'nft', 'nmcli', 'resolvectl', 'busctl', 'getent'}
    p = subprocess.run(argv, input=stdin, text=True, capture_output=True, env=ENV, timeout=timeout)
    if p.returncode:
        detail = 'WireGuard operation failed (redacted)' if argv[0] == 'wg' else ' '.join(argv) + ': ' + p.stderr.strip()
        raise RuntimeError(detail)
    return p.stdout


def check(name, ok, **evidence):
    CHECKS.append({'name': name, 'passed': bool(ok), **evidence})
    if not ok:
        raise AssertionError(name)


def write(path, data):
    guard()
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(data)


def spawn(name, args):
    guard()
    log = open('/run/' + name + '.log', 'w+')
    p = subprocess.Popen(args, stdout=log, stderr=log, env=ENV)
    CHILDREN.append((name, p, log))
    return p


def wait_for(name, test):
    deadline = time.monotonic() + 8
    error = ''
    while time.monotonic() < deadline:
        try:
            if test():
                return
        except Exception as exc:
            error = str(exc)
        time.sleep(.1)
    raise RuntimeError(name + ' not ready: ' + error)


def services():
    guard()
    check('private_namespace_and_filesystem_preflight', True, namespaces=CURRENT)
    check('no_inherited_service_sockets', not Path('/run/dbus/system_bus_socket').exists()
          and not Path('/run/systemd/private').exists() and not Path('/var/run/dbus/system_bus_socket').exists())
    # A fresh sysfs mount is rejected by this kernel's "too revealing" check.
    # Never substitute host /sys: use an empty private tmpfs, netlink remains real.
    check('sysfs_is_private_empty_tmpfs', not list(Path('/sys').iterdir()))
    cmd(['ip', 'link', 'set', 'lo', 'up'])
    write('/etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nsystemd-resolve:x:0:0:resolver:/run/systemd:/usr/bin/nologin\n')
    write('/etc/group', 'root:x:0:\n')
    write('/etc/nsswitch.conf', 'passwd: files\ngroup: files\nhosts: files dns\n')
    write('/etc/hosts', '127.0.0.1 localhost\n::1 localhost\n')
    write('/etc/machine-id', '0123456789abcdef0123456789abcdef\n')
    write('/etc/resolv.conf', 'nameserver 127.0.0.53\n')
    write('/etc/dbus-test.conf', '''<busconfig><type>system</type><listen>unix:path=/run/dbus/system_bus_socket</listen>
<auth>EXTERNAL</auth><policy context="default"><allow user="*"/><allow own="*"/>
<allow send_destination="*"/><allow receive_sender="*"/></policy></busconfig>''')
    Path('/run/dbus').mkdir()
    Path('/run/systemd/resolve').mkdir(parents=True)
    Path('/run/omarchy-wireguard').mkdir(mode=0o700)
    Path('/var/lib/NetworkManager').mkdir(parents=True)
    write('/etc/NetworkManager/NetworkManager.conf', '[main]\nplugins=keyfile\ndns=systemd-resolved\nrc-manager=unmanaged\nauth-polkit=false\n[logging]\nlevel=WARN\n[device]\nmatch-device=interface-name:*\nmanaged=1\n')
    Path('/etc/NetworkManager/conf.d').mkdir(parents=True, exist_ok=True)
    write('/etc/NetworkManager/conf.d/20-connectivity.conf', '[connectivity]\nenabled=false\n')
    write('/etc/systemd/resolved.conf', '[Resolve]\nDNS=\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\nDNSSEC=no\nDNSOverTLS=no\n')
    spawn('dbus', ['dbus-daemon', '--nofork', '--config-file=/etc/dbus-test.conf'])
    wait_for('dbus', lambda: Path('/run/dbus/system_bus_socket').exists())
    spawn('resolved', ['/usr/lib/systemd/systemd-resolved'])
    wait_for('resolved', lambda: bool(cmd(['resolvectl', 'status'])))
    spawn('nm', ['NetworkManager', '--no-daemon', '--config=/etc/NetworkManager/NetworkManager.conf'])
    wait_for('NetworkManager', lambda: 'running' in cmd(['nmcli', '-t', '-f', 'RUNNING', 'general']))
    check('real_private_nm_and_resolved_ready', True)


class Peer:
    def __init__(self):
        guard()
        log = open('/run/peer.log', 'w+')
        self.proc = subprocess.Popen(['unshare', '-n', '/usr/bin/python', '-B', '/test/peer.py', json.dumps(HOST)],
                                     stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=log, text=True, env=ENV)
        CHILDREN.append(('peer', self.proc, log))
        identity = self.receive()
        self.pid = identity['pid']
        check('peer_has_independent_network', identity['netns'] not in (HOST['net'], CURRENT['net']))

    def receive(self):
        with selectors.DefaultSelector() as sel:
            sel.register(self.proc.stdout, selectors.EVENT_READ)
            if not sel.select(5):
                raise RuntimeError('peer RPC timed out')
        result = json.loads(self.proc.stdout.readline())
        if 'error' in result:
            raise RuntimeError(result['error'])
        return result

    def call(self, op, **data):
        self.proc.stdin.write(json.dumps({'op': op, **data}) + '\n')
        self.proc.stdin.flush()
        return self.receive()

    def ip(self, *args):
        return self.call('ip', args=list(args))


def lifecycle(inject_failure, assert_import_inactive):
    from omarchy_wireguard.system import HostSystem, CommandRunner
    from omarchy_wireguard.controller import Controller
    from omarchy_wireguard.storage import StateStore

    import omarchy_wireguard.system as system_module
    original_publish = system_module.publish_keyfile
    import_probe = {}

    def probed_publish(text):
        guard()
        original_publish(text)
        if assert_import_inactive:
            # Same 300ms scheduling seam, now at the actual AddConnection2 return.
            time.sleep(.3)
            import_probe['publication_calls'] = import_probe.get('publication_calls', 0) + 1
            import_probe['active_during_import'] = cmd(['nmcli', '-t', '-f', 'NAME,TYPE', 'connection', 'show', '--active'])
            import_probe['wg_interfaces_during_import'] = cmd(['wg', 'show', 'interfaces']).split()
            import_probe['dns_during_import'] = cmd(['resolvectl', 'dns'])
            import_probe['route_during_import'] = json.loads(cmd(['ip', '-j', 'route', 'get', '1.1.1.1']))
            import_probe['routes6_during_import'] = json.loads(cmd(['ip', '-6', '-j', 'route', 'show', 'table', 'all']))
            import_probe['firewall_tables_during_import'] = cmd(['nft', 'list', 'tables'])
    system_module.publish_keyfile = probed_publish

    class GuardedRunner(CommandRunner):
        def run(self, argv, *, stdin=None, timeout=10):
            guard()
            assert argv[0] in {'nmcli', 'resolvectl', 'wg', 'nft', 'ip', 'getent'}
            # Execute the unmodified production CommandRunner, including its environment.
            output = super().run(argv, stdin=stdin, timeout=timeout)
            return output

    peer = Peer()
    cmd(['ip', 'link', 'add', 'eth0', 'type', 'veth', 'peer', 'name', 'ethpeer'])
    cmd(['ip', 'link', 'set', 'ethpeer', 'netns', str(peer.pid)])
    cmd(['ip', 'addr', 'add', '192.0.2.1/24', 'dev', 'eth0'])
    cmd(['ip', 'link', 'set', 'eth0', 'up'])
    cmd(['ip', 'route', 'add', 'default', 'via', '192.0.2.2', 'dev', 'eth0'])
    peer.ip('link', 'set', 'lo', 'up')
    peer.ip('addr', 'add', '192.0.2.2/24', 'dev', 'ethpeer')
    peer.ip('link', 'set', 'ethpeer', 'up')
    peer.ip('addr', 'add', '198.51.100.80/32', 'dev', 'lo')
    peer.ip('link', 'add', 'wgpeer', 'type', 'wireguard')
    peer.ip('addr', 'add', '10.77.0.1/24', 'dev', 'wgpeer')
    private = cmd(['wg', 'genkey']).strip()
    peer_private = cmd(['wg', 'genkey']).strip()
    public = cmd(['wg', 'pubkey'], private).strip()
    peer_public = cmd(['wg', 'pubkey'], peer_private).strip()
    peer.call('wg', config=f'[Interface]\nPrivateKey = {peer_private}\nListenPort = 51820\n[Peer]\nPublicKey = {public}\nAllowedIPs = 10.77.0.2/32\n')
    peer.ip('link', 'set', 'wgpeer', 'up')
    peer.call('start')
    cmd(['resolvectl', 'dns', 'eth0', '192.0.2.2'])
    cmd(['resolvectl', 'domain', 'eth0', 'original.test', '~original.test'])
    cmd(['resolvectl', 'default-route', 'eth0', 'yes'])
    system = HostSystem(GuardedRunner(), controller_uid=0)
    original_dns = system.capture_lan_dns(('eth0',))
    store = StateStore(Path('/var/lib/omarchy-wireguard'))
    controller = Controller(store, system, controller_uid=0)
    controller.boot()
    cmd(['nmcli', 'connection', 'add', 'type', 'dummy', 'ifname', 'unrelated0', 'con-name', 'unrelated-keep',
         'ipv4.method', 'disabled', 'ipv6.method', 'disabled', 'connection.autoconnect', 'no'])
    cmd(['nmcli', '--wait', '5', 'connection', 'up', 'unrelated-keep'])
    unrelated = cmd(['nmcli', '-g', 'connection.uuid', 'connection', 'show', 'unrelated-keep']).strip()
    check('unrelated_profile_initially_active', unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))
    config = f'[Interface]\nPrivateKey = {private}\nAddress = 10.77.0.2/24\nDNS = 10.77.0.1\n[Peer]\nPublicKey = {peer_public}\nAllowedIPs = 0.0.0.0/0\nEndpoint = 192.0.2.2:51820\nPersistentKeepalive = 1\n'
    write('/run/synthetic.conf', config)
    os.chmod('/run/synthetic.conf', 0o600)
    with open('/run/synthetic.conf', 'rb') as source:
        imported = controller.import_profiles(
            {'source': 'fd', 'name': 'synthetic.conf',
             'locations': {'synthetic.conf': {'country': 'Test', 'city': 'Private'}}},
            source_fd=source.fileno())
    check('real_controller_import', imported['imported'] and len(controller.catalog) == 1)
    check('import_tempfile_removed', not list(Path('/run/omarchy-wireguard').glob('import-*')))
    profile = controller.catalog[0]
    if assert_import_inactive:
        time.sleep(.3)
        active_after_import = cmd(['nmcli', '-g', 'GENERAL.STATE,GENERAL.DEVICES', 'connection', 'show', 'uuid', profile['uuid']]).strip()
        check('publication_probe_executed', import_probe.get('publication_calls') == 1)
        check('import_must_not_activate_before_connect', controller.mode == 'disabled' and not controller.enabled
              and 'activated' not in active_after_import
              and not any(line.rsplit(':', 1)[-1] == 'wireguard' for line in import_probe['active_during_import'].splitlines())
              and not import_probe['wg_interfaces_during_import']
              and '10.77.0.1' not in import_probe['dns_during_import']
              and all(r.get('dev') == 'eth0' for r in import_probe['route_during_import'])
              and all(r.get('dev') in ('lo', 'eth0', 'unrelated0') for r in import_probe['routes6_during_import'])
              and 'omarchy_wireguard' not in import_probe['firewall_tables_during_import'],
              controller_mode=controller.mode, actual_nm_state=active_after_import, **import_probe)
    settings = cmd(['nmcli', '-g', 'connection.autoconnect,wireguard.fwmark,ipv4.dns-priority,ipv4.dns-search', 'connection', 'show', 'uuid', profile['uuid']])
    check('nm_profile_hardened', 'no' in settings and '~.' in settings, settings=settings.strip())
    # Exercise the optional/dual-stack fields through actual libnm + D-Bus +
    # NM persistence. Compare secrets in memory; never put them in a report.
    import configparser
    from omarchy_wireguard.importer import parse_config
    from omarchy_wireguard.system import SystemFailure
    psk = cmd(['wg', 'genpsk']).strip()
    full = config.replace('Address = 10.77.0.2/24', 'Address = 10.77.0.2/24, 2001:db8::2/64')
    full = full.replace('DNS = 10.77.0.1', 'DNS = 10.77.0.1, 2001:db8::1\nMTU = 1400\nListenPort = 51821')
    full = full.replace('[Peer]', '[Peer]\nPresharedKey = ' + psk).replace('AllowedIPs = 0.0.0.0/0', 'AllowedIPs = 0.0.0.0/0, ::/0')
    extra_uuid = system.import_profile(parse_config('full.conf', full), 'omarchy-wireguard-full-fields')
    stored = None
    for path in Path('/etc/NetworkManager/system-connections').glob('*'):
        data = configparser.ConfigParser(interpolation=None)
        data.read(path)
        if data.get('connection', 'uuid', fallback='') == extra_uuid:
            stored = data
            check('nm_persisted_keyfile_mode_0600', path.stat().st_mode & 0o777 == 0o600)
    check('nm_roundtrip_all_wireguard_fields', stored is not None
          and stored['wireguard']['private-key'] == private
          and stored['wireguard']['mtu'] == '1400'
          and stored['wireguard']['listen-port'] == '51821'
          and stored['wireguard-peer.' + peer_public]['preshared-key'] == psk
          and stored['wireguard-peer.' + peer_public]['persistent-keepalive'] == '25'
          and '::/0' in stored['wireguard-peer.' + peer_public]['allowed-ips']
          and stored['wireguard-peer.' + peer_public]['endpoint'] == '192.0.2.2:51820'
          and stored['ipv6']['address1'] == '2001:db8::2/64'
          and stored['ipv6']['dns'] == '2001:db8::1;')
    system.delete_profile(extra_uuid)
    check('optional_profile_deleted', extra_uuid not in system.managed_profiles())
    before_failure = system.managed_profiles()
    def lost_reply(text):
        probed_publish(text)
        raise ValueError('injected lost publication reply')
    system_module.publish_keyfile = lost_reply
    rejected = False
    try:
        system.import_profile(parse_config('fail.conf', full), 'omarchy-wireguard-lost-reply')
    except SystemFailure:
        rejected = True
    finally:
        system_module.publish_keyfile = probed_publish
    check('real_post_add_failure_removes_only_new_profile', rejected and system.managed_profiles() == before_failure)
    controller.connect({'profile': profile['id']})
    controller.tick()
    check('controller_connected', controller.mode == 'connected', mode=controller.mode,
          error=controller.last_error, verification=controller.last_checks)
    if inject_failure:
        raise RuntimeError('injected post-activation abort')
    result = cmd(['resolvectl', 'query', '--type=A', 'outside.test'])
    check('public_dns_real_answer', '203.0.113.80' in result)
    result = cmd(['resolvectl', 'query', '--type=A', 'printer.lan'])
    check('lan_dns_real_answer', '192.0.2.88' in result)
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2)
    sock.sendto(b'tunnel-packet', ('198.51.100.80', 39071))
    check('real_udp_tunnel_echo', sock.recv(100) == b'tunnel-packet')
    sock.close()
    packets = peer.call('seen')['packets']
    check('public_dns_ingress_is_tunnel', any(p.get('name') == 'outside.test' and p['ingress'] == 'wgpeer' for p in packets), packets=packets)
    check('lan_dns_ingress_is_underlay', any(p.get('name') == 'printer.lan' and p['ingress'] == 'ethpeer' for p in packets))
    check('echo_ingress_is_tunnel', any(p.get('token') == 'tunnel-packet' and p['ingress'] == 'wgpeer' for p in packets))
    system.clear_tunnel_dns(controller.interface)
    check('adapter_clear_tunnel_dns_real_resolved', '~.' not in cmd(['resolvectl', 'domain', controller.interface])
          and '10.77.0.1' not in cmd(['resolvectl', 'dns', controller.interface]))
    system.configure_tunnel_dns(profile['uuid'], controller.interface)
    check('adapter_reconfigure_tunnel_dns', system.verify(profile['uuid'], controller.interface,
          firewall_context=controller.firewall_context).ok)
    # Process-state restart: real persisted StateStore and fresh unmodified Controller.
    controller = Controller(store, system, controller_uid=0)
    controller.boot()
    check('controller_restart_reconnects', controller.mode == 'connected', error=controller.last_error)
    check('restart_retains_original_dns_snapshot', controller.dns_restore == original_dns)
    check('unrelated_profile_survives_connect_restart', unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))
    # Real link loss, not a mocked verification failure.
    cmd(['ip', 'link', 'delete', controller.interface])
    controller.tick()
    check('tunnel_loss_enters_failed', controller.mode == 'failed', error=controller.last_error)
    check('tunnel_loss_retains_fail_closed_table', 'policy drop' in cmd(['nft', 'list', 'table', 'inet', 'omarchy_wireguard']))
    # Fresh counter reading ties the blocked packet to the production output rule.
    def drops():
        table = json.loads(cmd(['nft', '-j', 'list', 'table', 'inet', 'omarchy_wireguard']))
        return sum(expr['counter']['packets'] for item in table['nftables']
                   if str(item.get('rule', {}).get('comment', '')).endswith(':WireGuard fail closed')
                   for expr in item['rule']['expr'] if 'counter' in expr)
    before_drops = drops()
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(.4)
    blocked = False
    try:
        sock.sendto(b'failure-must-not-leak', ('198.51.100.80', 39071))
        sock.recv(100)
    except (PermissionError, socket.timeout):
        blocked = True
    finally:
        sock.close()
    check('tunnel_loss_public_udp_blocked', blocked and drops() > before_drops and not any(p.get('token') == 'failure-must-not-leak' for p in peer.call('seen')['packets']))
    check('unrelated_profile_survives_failure', unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))
    controller.retry({})
    controller.tick()
    check('retry_reconnects_real_nm', controller.mode == 'connected', error=controller.last_error)
    controller.disconnect({})
    check('disconnect_dns_restored', system.capture_lan_dns(('eth0',)) == original_dns)
    check('disconnect_no_managed_active', profile['uuid'] not in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))
    check('disconnect_firewall_removed', 'omarchy_wireguard' not in cmd(['nft', 'list', 'tables']))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(2)
        sock.sendto(b'disconnect-direct-control', ('198.51.100.80', 39071))
        check('disconnect_direct_udp_positive_control', sock.recv(100) == b'disconnect-direct-control'
              and any(p.get('token') == 'disconnect-direct-control' and p['ingress'] == 'ethpeer'
                      for p in peer.call('seen')['packets']))
    check('unrelated_profile_survives_disconnect', unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))
    answer = cmd(['resolvectl', 'query', '--type=A', 'restored.original.test'])
    check('restored_dns_answers_via_original_underlay', '192.0.2.88' in answer and any(
          p.get('name') == 'restored.original.test' and p['ingress'] == 'ethpeer' for p in peer.call('seen')['packets']))

    # Inject only a persistence failure; all NM import/delete operations remain real.
    from omarchy_wireguard.importer import ImportFailure
    class FailingCatalog(StateStore):
        def write(self, name, value):
            if name == 'profiles.json':
                raise OSError('injected catalog persistence failure')
            return super().write(name, value)
    before_profiles = cmd(['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'show'])
    failing = Controller(FailingCatalog(Path('/var/lib/failed-import')), system, controller_uid=0)
    refused = False
    try:
        with open('/run/synthetic.conf', 'rb') as source:
            failing.import_profiles(
                {'source': 'fd', 'name': 'synthetic.conf',
                 'locations': {'synthetic.conf': {'country': 'Test', 'city': 'Rollback'}}},
                source_fd=source.fileno())
    except ImportFailure:
        refused = True
    after_profiles = cmd(['nmcli', '-t', '-f', 'NAME,UUID', 'connection', 'show'])
    check('real_nm_import_rollback_on_persistence_failure', refused and sorted(before_profiles.splitlines()) == sorted(after_profiles.splitlines()))
    check('rollback_retains_unrelated_active_profile', unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show', '--active']))

    # Restart actual foreground service processes, not systemctl or a fake response.
    old_nm = next(proc for name, proc, log in CHILDREN if name == 'nm')
    old_nm.terminate()
    old_nm.wait(timeout=3)
    spawn('nm-restarted', ['NetworkManager', '--no-daemon', '--config=/etc/NetworkManager/NetworkManager.conf'])
    wait_for('restarted NetworkManager', lambda: 'running' in cmd(['nmcli', '-t', '-f', 'RUNNING', 'general']))
    check('nm_restart_retains_both_profile_keyfiles', profile['uuid'] in system.managed_profiles()
          and unrelated in cmd(['nmcli', '-t', '-f', 'UUID', 'connection', 'show']))
    controller = Controller(store, system, controller_uid=0)
    controller.boot()
    check('disabled_backend_restart_stays_disabled', controller.mode == 'disabled' and not controller.enabled)
    controller.connect({'profile': profile['id']})
    controller.tick()
    check('connect_after_real_nm_restart', controller.mode == 'connected', error=controller.last_error)
    controller.disconnect({})
    check('dns_restore_after_real_nm_restart', system.capture_lan_dns(('eth0',)) == original_dns)

    old_resolved = next(proc for name, proc, log in CHILDREN if name == 'resolved')
    old_resolved.terminate()
    old_resolved.wait(timeout=3)
    spawn('resolved-restarted', ['/usr/lib/systemd/systemd-resolved'])
    wait_for('restarted resolved', lambda: bool(cmd(['resolvectl', 'status'])))
    # Manual underlay was not provisioned by DHCP/NM: republish its synthetic baseline.
    cmd(['resolvectl', 'dns', 'eth0', '192.0.2.2'])
    system.restore_lan_dns(original_dns)
    controller.connect({'profile': profile['id']})
    controller.tick()
    check('connect_after_real_resolved_restart', controller.mode == 'connected', error=controller.last_error)
    answer = cmd(['resolvectl', 'query', '--type=A', 'after-restart.test'])
    check('real_dns_answer_after_resolved_restart', '203.0.113.80' in answer)
    controller.disconnect({})
    check('final_dns_snapshot_restored', system.capture_lan_dns(('eth0',)) == original_dns)


def main():
    global HOST, CURRENT
    parser = argparse.ArgumentParser()
    parser.add_argument('--host', required=True)
    parser.add_argument('--inject-failure', action='store_true')
    parser.add_argument('--assert-import-inactive', action='store_true')
    args = parser.parse_args()
    HOST = json.loads(args.host)
    guard()  # Deliberately outside exception handler: host guard self-test must fail.
    CURRENT = {k: os.readlink('/proc/self/ns/' + k) for k in HOST}
    result = {'status': 'blocked', 'checks': CHECKS}
    try:
        services()
        lifecycle(args.inject_failure, args.assert_import_inactive)
        result['status'] = 'passed'
    except Exception as exc:
        if isinstance(exc, AssertionError):
            result['status'] = 'failed'
        if args.inject_failure and str(exc) == 'injected post-activation abort':
            result['status'] = 'expected_abort'
        result['error'] = str(exc)
        result['logs'] = {}
        for name, proc, log in CHILDREN:
            log.flush()
            log.seek(0)
            result['logs'][name] = log.read()[-6000:]
    finally:
        for name, proc, log in reversed(CHILDREN):
            if proc.poll() is None:
                proc.terminate()
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=2)
            log.close()
        result['children_reaped'] = all(p.poll() is not None for _, p, _ in CHILDREN)
    print(json.dumps(result))
    return 0 if result['status'] == 'passed' else 1


if __name__ == '__main__':
    sys.exit(main())
