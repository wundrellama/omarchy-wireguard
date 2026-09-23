#!/usr/bin/env python3
"""Real QML/Process test using synthetic NM and sysfs helper output, no network."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="wg-traffic-", dir=os.environ["TMPDIR"]) as directory:
    stage = Path(directory)
    for name in ("TrafficService.qml", "Traffic.js"):
        shutil.copy2(ROOT / "plugin" / name, stage / name)
    (stage / "traffic.py").write_text('''import json, sys, time
print(json.dumps(dict(ok=True,profile=sys.argv[1],uuid="fixture",interface="owg-test",ifindex=7,time=time.monotonic(),rx=int(time.monotonic()*1000),tx=int(time.monotonic()*2000))))
''')
    (stage / "shell.qml").write_text('''import QtQuick
import Quickshell
ShellRoot {
  TrafficService { id: traffic; profile: "home" }
  Timer { interval: 1600; running: true; onTriggered: {
    console.log("TRAFFIC_RESULT " + JSON.stringify(traffic.traffic))
    traffic.profile = ""
    traffic.applySample('{"ok":true}', traffic.generation - 1, "home")
    console.log("DISCONNECTED " + JSON.stringify(traffic.traffic))
    Qt.quit()
  }}
}
''')
    result = subprocess.run(['/usr/bin/qs', '--no-color', '-p', str(stage/'shell.qml')],
                            capture_output=True, text=True, timeout=6,
                            env=dict(os.environ, QT_QPA_PLATFORM='offscreen'))
    output = result.stdout + result.stderr
    reports = [json.loads(line.split('TRAFFIC_RESULT ',1)[1]) for line in output.splitlines() if 'TRAFFIC_RESULT ' in line]
    assert result.returncode == 0 and len(reports) == 1, output
    report = reports[0]
    assert report and 900 < report['down'] < 1100 and 1900 < report['up'] < 2100, output
    assert 'DISCONNECTED null' in output, output
    assert 'ReferenceError' not in output and 'TypeError' not in output, output
    print(json.dumps(report))
    print('Real offscreen QML sampling, rates and disconnect passed')
