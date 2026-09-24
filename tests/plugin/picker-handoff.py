#!/usr/bin/python3
"""Exercise production Service with real Quickshell IO and inert CLI/picker children."""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]
with tempfile.TemporaryDirectory(prefix="wg-picker-", dir=os.environ["TMPDIR"]) as directory:
    stage = Path(directory)
    for name in ("Service.qml", "Model.js", "Proton.js", "ProtonService.qml", "TrafficService.qml", "Traffic.js", "traffic.py"):
        shutil.copy2(ROOT / "plugin" / name, stage / name)
    commands = stage / "bin"
    commands.mkdir()
    cli = commands / "omarchy-wireguard"
    cli.write_text('''#!/usr/bin/python3
import json,sys
if sys.argv[1] == "status":
    print(json.dumps({"ok":True,"result":{"mode":"disabled","enabled":False}}))
elif sys.argv[1] == "list":
    print(json.dumps({"ok":True,"result":{"profiles":[],"locations":[]}}))
elif sys.argv[1] == "import":
    print(json.dumps({"ok":True,"result":{"review_required":["synthetic.conf"]}}))
else:
    raise SystemExit("unexpected test command")
''')
    cli.chmod(0o755)
    picker = commands / "omarchy-file-select"
    picker.write_text('#!/bin/bash\nprintf "/synthetic.conf\\n"\n')
    picker.chmod(0o755)
    # Never send desktop notifications, even if a regression produces an error.
    notify = commands / "omarchy-notification-send"
    notify.write_text('#!/bin/bash\nexit 0\n')
    notify.chmod(0o755)
    # Inert Proton adapter inputs: the real protonvpn/nmcli in /usr/bin never run.
    for tool, body in (("protonvpn", '#!/bin/bash\n[ "$1" = status ] && echo "Status: Disconnected"\n[ "$1" = info ] && echo "Account: \'None\'"\nexit 0\n'),
                       ("nmcli", "#!/bin/bash\nexit 0\n")):
        (commands / tool).write_text(body)
        (commands / tool).chmod(0o755)
    (stage / "shell.qml").write_text('''import QtQuick
import Quickshell
ShellRoot {
  Service { id: service; active: false }
  Component.onCompleted: service.active = true
  Timer {
    interval: 200; running: true
    onTriggered: {
      service.applyStatus('{"mode":"disabled","enabled":false}')
      service.panelOpen = false
      service.chooseImport(false)
    }
  }
  Timer {
    interval: 1600; running: true
    onTriggered: {
      console.log("PICKER_RESULT " + JSON.stringify({
        paths: service.importPaths,
        review: service.status.importReview,
        error: service.actionError,
        busy: service.busy
      }))
      Qt.quit()
    }
  }
}
''')
    env = dict(os.environ, PATH=str(commands) + ":/usr/bin", QT_QPA_PLATFORM="offscreen")
    result = subprocess.run(["/usr/bin/qs", "--no-color", "-p", str(stage / "shell.qml")],
                            capture_output=True, text=True, env=env, timeout=8)
    output = result.stdout + result.stderr
    reports = [json.loads(line.split("PICKER_RESULT ", 1)[1]) for line in output.splitlines() if "PICKER_RESULT " in line]
    assert result.returncode == 0 and len(reports) == 1, output
    report = reports[0]
    print(json.dumps(report))
    assert report["paths"] == ["/synthetic.conf"], "picker result was lost"
    assert report["review"].get("ambiguous") is True, "picker selection never reached import review"
    assert not report["busy"] and not report["error"], "picker/import did not finish cleanly"
    print("Real Quickshell picker handoff passed")
