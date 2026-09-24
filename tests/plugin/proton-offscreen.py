#!/usr/bin/python3
"""Run the production Service + ProtonService in offscreen Quickshell.

Synthetic `omarchy-wireguard`, `protonvpn` and `nmcli` executables on an
isolated PATH record every call. No real VPN, backend or NetworkManager
command runs. Scenario 1 switches WireGuard -> Proton and checks ordering.
Scenario 2 refuses Proton -> WireGuard when Proton's kill switch is on.
"""
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile

ROOT = Path(__file__).resolve().parents[2]

FAKE_WG = r'''#!/usr/bin/python3
import json, os, sys
state = os.path.join(os.environ["FAKE_STATE"], "wg-enabled")
open(os.path.join(os.environ["FAKE_STATE"], "log"), "a").write("omarchy-wireguard " + " ".join(sys.argv[1:]) + "\n")
enabled = os.path.exists(state)
if sys.argv[1] == "status":
    mode = "connected" if enabled else "disabled"
    print(json.dumps({"ok": True, "result": {"mode": mode, "enabled": enabled, "current_profile": "home" if enabled else None}}))
elif sys.argv[1] == "list":
    print(json.dumps({"ok": True, "result": {"profiles": [{"id": "home", "label": "Home"}]}}))
elif sys.argv[1] == "disconnect":
    if os.path.exists(state): os.unlink(state)
    print(json.dumps({"ok": True, "result": {"mode": "disabled", "enabled": False}}))
elif sys.argv[1] == "connect":
    open(state, "w").close()
    print(json.dumps({"ok": True, "result": {"mode": "connecting", "enabled": True}}))
else:
    raise SystemExit("unexpected test command")
'''

FAKE_PROTON = r'''#!/usr/bin/python3
import os, sys
d = os.environ["FAKE_STATE"]
state = os.path.join(d, "proton-server")
open(os.path.join(d, "log"), "a").write("protonvpn " + " ".join(sys.argv[1:]) + "\n")
args = sys.argv[1:]
if args == ["status"]:
    if os.path.exists(state):
        print("Status: Connected\nServer: CH#12 in Zurich, Switzerland\nLoad: 34%\nProtocol: wireguard")
    else:
        print("Status: Disconnected")
elif args == ["info"]:
    print("Account: 'synthetic@example.invalid'")
elif args == ["countries", "list"]:
    print("Country                           Code\n--------------------------------  ------\nSwitzerland                       CH")
elif args == ["config", "list"]:
    print("Setting                  Value\n-----------------------  ------------\nkill-switch              " + os.environ["FAKE_KILL_SWITCH"])
elif args[:1] == ["connect"]:
    open(state, "w").write("CH#12")
    print("Connected to CH#12 in Zurich, Switzerland.")
elif args == ["disconnect"]:
    if os.path.exists(state): os.unlink(state)
    print("Disconnected.")
else:
    print("Error: unexpected test command", file=sys.stderr); raise SystemExit(2)
'''

FAKE_NMCLI = r'''#!/usr/bin/python3
import os
d = os.environ["FAKE_STATE"]
if os.path.exists(os.path.join(d, "proton-server")):
    print("ProtonVPN CH#12:4bd6ef4f-ca1a-4756-b9d2-55678bee6008:wireguard:proton0:activated")
print("Synthetic Wi-Fi:1bd6ef4f-ca1a-4756-b9d2-55678bee6008:802-11-wireless:wlan0:activated")
'''

SCENARIOS = {
    "wg-to-proton": ("""
      if (step === 1) service.connectProton({ kind: "country", country: "CH" })
      if (step === 2) service.confirmSwitch()
    """, "off", True, False),
    "proton-to-wg-refused": ("""
      if (step === 1) service.connectLocation({ id: "home", kind: "profile", label: "Home" })
      if (step === 2) service.confirmSwitch()
    """, "standard", False, True),
    "proton-to-wg": ("""
      if (step === 1) service.connectLocation({ id: "home", kind: "profile", label: "Home" })
      if (step === 2) service.confirmSwitch()
    """, "off", False, True),
    # protonvpn is on PATH but cannot be launched (missing interpreter).
    "proton-launch-fails": ("""
      if (step === 1) service.connectProton({ kind: "country", country: "CH" })
      if (step === 2) service.confirmSwitch()
    """, "off", True, False),
}


def run(name):
    actions, kill_switch, wg_enabled, proton_connected = SCENARIOS[name]
    with tempfile.TemporaryDirectory(prefix="wg-proton-", dir=os.environ.get("TMPDIR")) as directory:
        stage = Path(directory)
        for item in ("Service.qml", "Model.js", "Proton.js", "ProtonService.qml", "TrafficService.qml", "Traffic.js", "traffic.py"):
            shutil.copy2(ROOT / "plugin" / item, stage / item)
        state = stage / "state"
        state.mkdir()
        if wg_enabled:
            (state / "wg-enabled").touch()
        if proton_connected:
            (state / "proton-server").write_text("CH#12")
        commands = stage / "bin"
        commands.mkdir()
        for tool, body in (("omarchy-wireguard", FAKE_WG), ("protonvpn", FAKE_PROTON), ("nmcli", FAKE_NMCLI),
                           ("omarchy-notification-send", "#!/bin/sh\nexit 0\n")):
            path = commands / tool
            if tool == "protonvpn" and name == "proton-launch-fails":
                body = "#!/nonexistent/interpreter\n"
            path.write_text(body)
            path.chmod(0o755)
        (stage / "shell.qml").write_text('''import QtQuick
import Quickshell
ShellRoot {
  Service { id: service; active: true; panelOpen: true }
  property int step: 0
  Timer {
    interval: 2500; running: true; repeat: true
    onTriggered: {
      step++
      %s
      if (step === 6) {
        console.log("PROTON_RESULT " + JSON.stringify({
          wg: service.status.state, proton: service.protonStatus.state, server: service.protonStatus.server,
          account: service.protonStatus.account, shield: service.shield.state, vpn: service.shield.vpn,
          phase: service.switchPhase, request: service.switchRequest, error: service.actionError,
          countries: service.proton.countries.length, busy: service.busy }))
        Qt.quit()
      }
    }
  }
}
''' % actions)
        env = dict(os.environ, PATH=str(commands) + ":/usr/bin", QT_QPA_PLATFORM="offscreen",
                   FAKE_STATE=str(state), FAKE_KILL_SWITCH=kill_switch)
        result = subprocess.run(["/usr/bin/qs", "--no-color", "-p", str(stage / "shell.qml")],
                                capture_output=True, text=True, env=env, timeout=40)
        output = result.stdout + result.stderr
        reports = [json.loads(line.split("PROTON_RESULT ", 1)[1]) for line in output.splitlines() if "PROTON_RESULT " in line]
        assert result.returncode == 0 and len(reports) == 1, output
        assert "ReferenceError" not in output and "TypeError" not in output, output
        log = (state / "log").read_text().splitlines() if (state / "log").exists() else []
        return reports[0], log


report, log = run("wg-to-proton")
print(json.dumps(report))
mutations = [line for line in log if line.split()[1] in ("connect", "disconnect")]
assert mutations == ["omarchy-wireguard disconnect", "protonvpn connect --country CH"], mutations
disconnect_at = log.index("omarchy-wireguard disconnect")
connect_at = log.index("protonvpn connect --country CH")
# A WireGuard status poll after the disconnect precedes the Proton connect.
assert "omarchy-wireguard status" in log[disconnect_at + 1:connect_at], log
assert report["wg"] == "disabled" and report["proton"] == "connected" and report["server"] == "CH#12", report
assert report["shield"] == "connected" and report["vpn"] == "Proton" and report["phase"] == "", report
assert report["account"] == "signed-in" and report["countries"] == 1 and not report["error"], report
print("WireGuard -> Proton switch ordering passed")

report, log = run("proton-to-wg-refused")
print(json.dumps(report))
mutations = [line for line in log if line.split()[1] in ("connect", "disconnect")]
assert mutations == [], mutations
assert "protonvpn config list" in log, log
assert report["proton"] == "connected" and report["wg"] == "disabled" and report["phase"] == "", report
assert "kill switch is standard" in report["error"], report
print("Proton -> WireGuard kill-switch refusal passed")

report, log = run("proton-to-wg")
print(json.dumps(report))
mutations = [line for line in log if line.split()[1] in ("connect", "disconnect")]
assert mutations == ["protonvpn disconnect", "omarchy-wireguard connect --profile home"], mutations
between = log[log.index("protonvpn disconnect") + 1:log.index("omarchy-wireguard connect --profile home")]
assert "protonvpn status" in between, log
assert log.index("protonvpn config list") < log.index("protonvpn disconnect"), log
assert report["proton"] == "disconnected" and report["wg"] == "connected" and report["vpn"] == "WireGuard", report
assert report["phase"] == "" and not report["error"], report
print("Proton -> WireGuard switch ordering passed")

report, log = run("proton-launch-fails")
print(json.dumps(report))
assert [line for line in log if line.startswith("protonvpn")] == [], log
assert report["phase"] == "" and not report["busy"], report
assert report["proton"] != "connected" and report["shield"] != "connected", report
assert "Could not run protonvpn" in report["error"], report
print("Proton launch failure ends the switch passed")
