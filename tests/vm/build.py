#!/usr/bin/env python3
"""Build a secret-free, RAM-only Arch userspace initramfs; never needs host root."""
import argparse
import gzip
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

parser = argparse.ArgumentParser()
parser.add_argument('--output', required=True, type=Path)
args = parser.parse_args()
D = args.output.resolve()
D.mkdir(parents=True, exist_ok=True)
R = D / 'root'
if R.exists():
    raise SystemExit('Use a new output directory; refusing to overwrite a guest tree')
R.mkdir()
HERE = Path(__file__).resolve().parent
REPO = HERE.parent.parent
seen = set()

def copy(path):
    path = Path(path)
    # Dependencies must be public installed /usr content, not host /etc or home.
    real = path.resolve()
    if not real.is_relative_to('/usr'):
        raise RuntimeError(f'Not a public /usr dependency: {path} -> {real}')
    dest = R / str(path).lstrip('/')
    dest.parent.mkdir(parents=True, exist_ok=True)
    shutil.copy2(path, dest, follow_symlinks=True)

def binary(path):
    path = str(path)
    if path in seen:
        return
    seen.add(path)
    copy(path)
    out = subprocess.run(['ldd', path], capture_output=True, text=True).stdout
    for dep in re.findall(r'(?:=>\s+|^\s*)(/[^\s]+)', out, re.M):
        binary(dep)

def text(path, content, mode=0o644):
    p = R / path
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content)
    p.chmod(mode)

for p in ('usr/bin', 'usr/lib', 'etc/systemd/system', 'proc', 'sys', 'dev', 'run', 'tmp', 'var/log', 'var/lib', 'root', 'home/vmuser', 'etc/NetworkManager/system-connections', 'etc/dbus-1/system.d'):
    (R / p).mkdir(parents=True, exist_ok=True)
for a, b in [('bin', 'usr/bin'), ('sbin', 'usr/bin'), ('lib', 'usr/lib'), ('lib64', 'usr/lib')]:
    (R / a).symlink_to(b)
for name in ('man gzip nroff groff grotty troff preconv tbl eqn soelim sed locale basename bash mount systemctl systemd-analyze journalctl busctl resolvectl cat sleep true false test uname python3 nft wg ip nmcli NetworkManager dbus-daemon modprobe depmod id dirname find grep install mktemp cp chown chmod mv rm getent cut runuser env timeout stat mkdir ln').split():
    binary('/usr/bin/' + name)
for name in ('systemd', 'systemd-executor', 'systemd-resolved', 'systemd-journald'):
    binary('/usr/lib/systemd/' + name)
for path in ('/usr/bin/col', '/usr/lib/man-db/zsoelim', '/usr/lib/man-db/manconv', '/usr/lib/libkmod.so.2', '/usr/lib/libbpf.so.1', '/usr/lib/security/pam_permit.so', '/usr/lib/libnss_systemd.so.2'):
    binary(path)
(R / 'usr/bin/sh').symlink_to('bash')
# Host /usr/bin/python3 and its stdlib, excluding third-party packages and caches.
stdlib = Path(subprocess.check_output(['/usr/bin/python3', '-c', 'import sysconfig; print(sysconfig.get_path("stdlib"))'], text=True).strip())
for path in stdlib.rglob('*'):
    if any(part in ('site-packages', '__pycache__', 'test', 'tests', 'idlelib', 'tkinter', 'turtledemo') for part in path.relative_to(stdlib).parts):
        continue
    if path.is_file():
        binary(path) if path.suffix == '.so' else copy(path)
for dirname in ('/usr/lib/NetworkManager', '/usr/share/dbus-1/system.d', '/usr/share/groff'):
    for path in Path(dirname).rglob('*'):
        if path.is_file():
            binary(path) if '.so' in path.name else copy(path)
copy('/usr/share/dbus-1/system.conf')
for path in Path('/usr/share/man/man8').glob('NetworkManager.8*'):
    copy(path)
text('etc/man_db.conf', 'MANDATORY_MANPATH /usr/share/man\nMANDB_MAP /usr/share/man /var/cache/man\nSECTION 1 8 2 3 4 5 6 7 9\n')
# Stock units preserve real daemon sandboxing and dependency semantics. Only
# dbus.service is a synthetic launcher for the actual dbus-daemon implementation.
units = 'dbus.socket NetworkManager.service systemd-resolved.service systemd-resolved-varlink.socket systemd-resolved-monitor.socket systemd-journald.service systemd-journald.socket systemd-journald-dev-log.socket basic.target sysinit.target sockets.target paths.target timers.target local-fs.target local-fs-pre.target network.target network-pre.target nss-lookup.target multi-user.target shutdown.target umount.target final.target'.split()
for unit in units:
    copy('/usr/lib/systemd/system/' + unit)
# Selected modules plus actual dependency metadata; no module loads on host.
kernel = os.uname().release
for path in Path('/usr/lib/modules', kernel).glob('modules.*'):
    if path.is_file():
        copy(path)
for module in ('nf_tables', 'nft_ct', 'nft_fib_inet', 'nft_reject_inet', 'nft_chain_nat', 'wireguard', 'dummy'):
    result = subprocess.check_output(['modprobe', '--show-depends', module], text=True)
    for line in result.splitlines():
        if line.startswith('insmod '):
            copy(line.split()[1])
text('etc/os-release', 'ID=arch\nNAME="Disposable WireGuard systemd VM"\n')
text('etc/passwd', 'root:x:0:0:root:/root:/bin/sh\nvmuser:x:1000:1000:VM controller:/home/vmuser:/bin/bash\ndbus:x:81:81:D-Bus:/:/usr/bin/false\nsystemd-resolve:x:978:978:resolver:/:/usr/bin/false\n')
text('etc/group', 'root:x:0:\nvmuser:x:1000:\ndbus:x:81:\nsystemd-resolve:x:978:\nsystemd-journal:x:190:\n')
text('etc/nsswitch.conf', 'passwd: files\ngroup: files\nshadow: files\nhosts: files dns\n')
text('etc/machine-id', '')
text('etc/pam.d/runuser', 'auth required pam_permit.so\naccount required pam_permit.so\nsession required pam_permit.so\n')
text('etc/NetworkManager/NetworkManager.conf', '[main]\nplugins=keyfile\ndns=systemd-resolved\n[connectivity]\nenabled=false\n')
text('etc/systemd/resolved.conf', '[Resolve]\nFallbackDNS=\nLLMNR=no\nMulticastDNS=no\n')
text('etc/systemd/system/dbus.service', '[Unit]\nDescription=Real dbus-daemon synthetic guest launcher\nDefaultDependencies=no\nRequires=dbus.socket\nAfter=dbus.socket\n[Service]\nType=notify\nRuntimeDirectory=dbus\nExecStart=/usr/bin/dbus-daemon --system --nofork --nopidfile --systemd-activation --address=systemd:\n')
text('etc/systemd/system/vm-proof.target', '[Unit]\nDefaultDependencies=no\nWants=vm-proof.service\n')
text('etc/systemd/system/vm-proof.service', '[Unit]\nDefaultDependencies=no\nWants=systemd-journald.service\nAfter=systemd-journald.service\n[Service]\nType=oneshot\nExecStart=/bin/bash /vm-proof.sh\nStandardOutput=tty\nStandardError=tty\nTTYPath=/dev/console\nTimeoutStartSec=150\n')
text('init', '#!/bin/sh\nmount -t proc proc /proc\nmount -t sysfs sysfs /sys\nmount -t devtmpfs devtmpfs /dev\nexec >/dev/console 2>&1\nmount -t tmpfs tmpfs /run\nmkdir -p /dev/shm /run/user/1000\nmount -t tmpfs tmpfs /dev/shm\nchmod 1777 /tmp /dev/shm\nchown 1000:1000 /home/vmuser /run/user/1000\nexec /usr/lib/systemd/systemd --system --unit=vm-proof.target\n', 0o755)
text('vm-proof.sh', '#!/bin/bash\nexport PATH=/usr/bin:/bin LC_ALL=C\n/usr/bin/python3 -u /guest.py\nrc=$?\necho VM_GUEST_EXIT=$rc\nsystemctl --force --force poweroff\n', 0o755)
text('vm-fault.sh', '#!/bin/bash\nset -eu\ninstall -m 0644 /repo/packaging/systemd/50-omarchy-wireguard.conf /etc/systemd/system/NetworkManager.service.d/50-omarchy-wireguard.conf\nsystemctl daemon-reload\nsystemctl show NetworkManager.service -p Requires > /run/vm-fault-edge\nexit 23\n', 0o755)
shutil.copy2(HERE / 'guest.py', R / 'guest.py')
# Explicit allowlist: project code only, no .git, profiles, user configs or secrets.
manifest = {}
for directory in ('backend/omarchy_wireguard', 'bin', 'scripts', 'packaging/systemd'):
    for source in (REPO / directory).rglob('*'):
        if source.is_file() and '__pycache__' not in source.parts:
            if source.is_symlink():
                raise RuntimeError(f'Project symlink prohibited: {source}')
            relative = source.relative_to(REPO)
            target = R / 'repo' / relative
            target.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, target)
            manifest[str(relative)] = hashlib.sha256(source.read_bytes()).hexdigest()
shutil.copy2(REPO / 'manifest.json', R / 'repo/manifest.json')
# Sole inert boundary: no Omarchy desktop/menu exists in this guest.
text('repo/scripts/integrate-user', '#!/bin/bash\nprintf "VM_GUI_STUB integrate-user %s\\n" "$1"\n', 0o755)
(D / 'snapshot-sha256.json').write_text(json.dumps(manifest, indent=2) + '\n')
paths = ['.'] + [str(p.relative_to(R)) for p in R.rglob('*')]
with (D / 'initramfs.cpio.gz').open('wb') as output:
    cp = subprocess.Popen(['cpio', '--null', '-o', '--format=newc', '--owner=0:0'], stdin=subprocess.PIPE, stdout=subprocess.PIPE, cwd=R)
    # Feed filenames independently to avoid pipe backpressure deadlock.
    import threading
    def feed():
        cp.stdin.write(('\0'.join(paths) + '\0').encode())
        cp.stdin.close()
    thread = threading.Thread(target=feed)
    thread.start()
    with gzip.GzipFile(fileobj=output, mode='wb', compresslevel=1) as compressed:
        shutil.copyfileobj(cp.stdout, compressed)
    thread.join()
    if cp.wait():
        raise SystemExit('cpio failed')
print(json.dumps({'output': str(D), 'kernel': kernel, 'copied_binary_dependencies': len(seen), 'initramfs_bytes': (D / 'initramfs.cpio.gz').stat().st_size}))
