#!/usr/bin/env python3
"""Bound QEMU, retain serial evidence, require guest assertions and exit marker."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys

p = argparse.ArgumentParser()
p.add_argument('--image', required=True, type=Path)
p.add_argument('--qemu-root', required=True, type=Path)
p.add_argument('--timeout', type=int, default=180)
a = p.parse_args()
if not 1 <= a.timeout <= 240:
    p.error('timeout must be 1..240 seconds')
d = a.image.resolve()
q = a.qemu_root.resolve()
cmd = [str(q / 'usr/bin/qemu-system-x86_64'), '-L', str(q / 'usr/share/qemu'), '-bios', str(q / 'usr/share/qemu/bios-256k.bin'), '-machine', 'q35,accel=kvm', '-cpu', 'host', '-m', '1536M', '-smp', '2', '-nodefaults', '-no-reboot', '-display', 'none', '-serial', 'stdio', '-monitor', 'none', '-nic', 'none', '-kernel', f'/usr/lib/modules/{os.uname().release}/vmlinuz', '-initrd', str(d / 'initramfs.cpio.gz'), '-append', 'console=ttyS0 rdinit=/init panic=-1 loglevel=4 systemd.log_level=info systemd.log_target=console systemd.show_status=1']
env = dict(os.environ, LD_LIBRARY_PATH=str(q / 'usr/lib'))
proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, env=env, start_new_session=True)
timed_out = False
try:
    output, _ = proc.communicate(timeout=a.timeout)
except subprocess.TimeoutExpired:
    timed_out = True
    os.killpg(proc.pid, signal.SIGTERM)
    try:
        output, _ = proc.communicate(timeout=5)
    except subprocess.TimeoutExpired:
        os.killpg(proc.pid, signal.SIGKILL)
        output, _ = proc.communicate()
finally:
    if proc.poll() is None:
        os.killpg(proc.pid, signal.SIGKILL)
        proc.wait()
(d / 'serial.log').write_bytes(output)
text = output.decode(errors='replace')
results = [json.loads(line.split('VM_RESULT ', 1)[1]) for line in text.splitlines() if line.startswith('VM_RESULT ')]
markers = [line.strip() for line in text.splitlines() if line.startswith('VM_GUEST_EXIT=')]
assertions = [line.strip().split('VM_ASSERT_PASS ', 1)[1] for line in text.splitlines() if line.startswith('VM_ASSERT_PASS ')]
passed = (not timed_out and proc.returncode == 0 and len(results) == 1 and results[0].get('ok') is True and results[0].get('guest_exit') == 0 and markers == ['VM_GUEST_EXIT=0'] and results[0].get('assertions') == assertions and len(assertions) >= 30)
summary = {'passed': passed, 'qemu_exit': proc.returncode, 'timed_out': timed_out, 'guest_exit_markers': markers, 'assertion_count': len(assertions), 'result': results, 'serial_log': str(d / 'serial.log'), 'snapshot_hashes': str(d / 'snapshot-sha256.json'), 'command': cmd}
(d / 'result.json').write_text(json.dumps(summary, indent=2) + '\n')
print(json.dumps(summary, indent=2))
if not passed:
    print(text[-16000:])
sys.exit(0 if passed else 1)
