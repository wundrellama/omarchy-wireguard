import QtQuick
import Quickshell
import Quickshell.Io
import "Proton.js" as Proton

// Read-mostly adapter for the official proton-vpn-cli running in the user
// session. Credentials stay in Proton's own client: sign-in opens Proton's
// interactive prompt in a terminal, and no account value is stored here.
// Every command is a fixed argv; user choices are validated by Proton.js.
Item {
  id: root

  property bool active: true
  property bool panelOpen: false
  property string phase: ""
  property var installed: null
  property string account: "unknown"
  property var nm: ({ ok: false, at: 0, match: "none", server: "", activated: false })
  property var cli: ({ ok: false, at: 0, state: "unknown" })
  property string action: ""
  property string error: ""
  property string message: ""
  property double clock: Date.now()
  property int generation: 0
  property var countries: []
  property string countriesError: ""
  property var cities: ({})
  property string citiesError: ""
  // Compact index from proton_servers.py; read-only, loaded once per session.
  property var servers: []
  property string serversError: ""
  readonly property string serversHelper: decodeURIComponent(String(Qt.resolvedUrl("proton_servers.py")).replace(/^file:\/\//, ""))
  readonly property bool busy: actionProcess.running || configProcess.running
  readonly property var status: Proton.buildStatus({ installed: installed, action: action, nm: nm, cli: cli,
    now: clock, phase: phase, error: error, message: message, account: account })

  signal actionDone(string action, bool success, string message)
  signal killSwitchRead(string value)
  signal observed()

  function start(process, command, timeoutMs) {
    process.startedAt = Date.now()
    process.timeoutMs = timeoutMs
    process.revision = generation
    process.command = command
    process.handledExit = false
    process.running = true
    launchCheck.restart()
  }

  // Advance the cached clock before publishing an observation. Otherwise an
  // observation can look future-dated until the one-second clock timer runs.
  function storeNm(parsed, observedAt) {
    var at = Number(observedAt)
    if (!isFinite(at) || at <= 0) at = Date.now()
    clock = Math.max(clock, at)
    parsed.at = at
    nm = parsed
  }

  function storeCli(parsed, observedAt) {
    var at = Number(observedAt)
    if (!isFinite(at) || at <= 0) at = Date.now()
    clock = Math.max(clock, at)
    parsed.at = at
    cli = parsed
  }

  // Quickshell emits no exited signal when a command cannot be launched, so a
  // one-shot check finishes any started command that is neither running nor
  // exited. Abandoned (revision -1) commands are ignored.
  function checkLaunches() {
    var failed = "Could not run protonvpn"
    var processes = [probeProcess, nmProcess, statusProcess, infoProcess, actionProcess, configProcess, countriesProcess, citiesProcess, serversProcess]
    for (var i = 0; i < processes.length; i++) {
      var process = processes[i]
      if (process.running || process.handledExit || process.revision === -1) continue
      process.handledExit = true
      if (!active) continue
      if (process === probeProcess) installed = null
      else if (process === nmProcess) { if (process.revision === generation) storeNm({ ok: false, match: "none", server: "", activated: false }, Date.now()) }
      else if (process === statusProcess) { if (process.revision === generation) storeCli({ ok: false, state: "unknown" }, Date.now()) }
      else if (process === infoProcess) account = "unknown"
      else if (process === actionProcess) {
        storeCli({ ok: false, state: "unknown" }, Date.now())
        finishAction(action, false, failed)
      }
      else if (process === configProcess) Qt.callLater(function() { root.killSwitchRead("") })
      else if (process === countriesProcess) countriesError = failed
      else if (process === citiesProcess) citiesError = failed
      else if (process === serversProcess) serversError = "Could not read the Proton server list"
    }
  }

  function refresh() {
    if (!active) return
    if (!nmProcess.running) start(nmProcess, ["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,STATE", "connection", "show", "--active"], 3000)
    if (installed === null && !probeProcess.running) start(probeProcess, ["sh", "-c", "command -v protonvpn"], 3000)
    if (installed !== true) return
    if (!statusProcess.running && !actionProcess.running) start(statusProcess, ["protonvpn", "status"], 20000)
  }

  function refreshAccount() {
    if (!active || installed !== true || infoProcess.running) return
    start(infoProcess, ["protonvpn", "info"], 20000)
  }

  function connect(choice) {
    var args = Proton.connectArgs(choice)
    if (!active || installed !== true || busy || !args) return false
    generation++
    action = "connect"
    error = ""
    message = "Connecting Proton VPN: " + Proton.choiceLabel(choice)
    start(actionProcess, ["protonvpn"].concat(args), 120000)
    return true
  }

  function disconnect() {
    if (!active || installed !== true || busy) return false
    generation++
    action = "disconnect"
    error = ""
    message = "Disconnecting Proton VPN"
    start(actionProcess, ["protonvpn", "disconnect"], 60000)
    return true
  }

  function readKillSwitch() {
    if (!active || installed !== true || busy) return false
    start(configProcess, ["protonvpn", "config", "list"], 20000)
    return true
  }

  function signIn() {
    if (!active || installed !== true) return
    // Fixed command string; the username is read by the terminal, never by the plugin.
    // `--` stops click option parsing so a typed name starting with "-" stays the USERNAME.
    Quickshell.execDetached(["omarchy-launch-floating-terminal-with-presentation", "read -rp 'Proton username: ' u && protonvpn signin -- \"$u\""])
    message = "Finish sign-in in the terminal, then open this panel again"
  }

  function loadCountries(force) {
    if (!active || installed !== true || countriesProcess.running) return
    if (countries.length > 0 && force !== true) return
    countriesError = ""
    start(countriesProcess, ["protonvpn", "countries", "list"], 30000)
  }

  function loadCities(code) {
    if (!active || installed !== true || citiesProcess.running || !Proton.validCountryCode(code)) return
    if (cities[code] && cities[code].length > 0) return
    citiesError = ""
    citiesProcess.code = code
    start(citiesProcess, ["protonvpn", "cities", "list", code], 30000)
  }

  function loadServers(force) {
    if (!active || installed !== true || serversProcess.running) return
    if (servers.length > 0 && force !== true) return
    serversError = ""
    start(serversProcess, ["python3", "-B", serversHelper], 20000)
  }

  function finishAction(name, success, text) {
    action = ""
    message = ""
    error = success ? "" : text
    generation++
    // Quickshell emits exited before runningChanged; let busy settle first.
    Qt.callLater(function() {
      if (!root.active) return
      root.actionDone(name, success, text)
      root.refresh()
    })
  }

  function expire() {
    clock = Date.now()
    var processes = [probeProcess, nmProcess, statusProcess, infoProcess, actionProcess, configProcess, countriesProcess, citiesProcess, serversProcess]
    for (var i = 0; i < processes.length; i++) {
      var process = processes[i]
      if (!process.running || clock - process.startedAt <= process.timeoutMs) continue
      process.revision = -1
      process.running = false
      if (process === actionProcess) finishAction(action, false, "Proton VPN command timed out; status is unknown until the next check")
      else if (process === configProcess) Qt.callLater(function() { root.killSwitchRead("") })
      else if (process === probeProcess) installed = null
    }
  }

  function setCities(code, list) {
    var next = ({})
    for (var key in cities) next[key] = cities[key]
    next[code] = list
    cities = next
  }

  Component.onCompleted: refresh()
  onPanelOpenChanged: if (panelOpen) { refresh(); refreshAccount(); loadCountries(false); loadServers(false) }
  onInstalledChanged: if (installed === true) { refresh(); refreshAccount(); if (panelOpen) { loadCountries(false); loadServers(false) } }
  onActiveChanged: if (!active) {
    for (var i = 0, list = [probeProcess, nmProcess, statusProcess, infoProcess, actionProcess, configProcess, countriesProcess, citiesProcess, serversProcess]; i < list.length; i++) {
      list[i].revision = -1
      list[i].running = false
    }
  }

  Timer { interval: 1000; repeat: true; running: root.active; onTriggered: root.expire() }
  // nmcli is cheap and drives the bar; the Python CLI runs when useful only.
  Timer {
    interval: root.panelOpen || root.phase !== "" || root.action !== "" ? 1500 : 3000
    repeat: true
    running: root.active
    onTriggered: if (!nmProcess.running) root.start(nmProcess, ["nmcli", "-t", "-f", "NAME,UUID,TYPE,DEVICE,STATE", "connection", "show", "--active"], 3000)
  }
  Timer {
    interval: root.panelOpen || root.phase !== "" ? 5000 : 10000
    repeat: true
    running: root.active && root.installed === true
    onTriggered: if (!statusProcess.running && !actionProcess.running) root.start(statusProcess, ["protonvpn", "status"], 20000)
  }

  component Command: Process {
    property double startedAt: 0
    property double timeoutMs: 0
    property int revision: -1
    property bool handledExit: true
    readonly property bool current: revision === root.generation
    onRunningChanged: if (!running) launchCheck.restart()
    // Connected rather than onExited: each instance declares its own onExited.
    Component.onCompleted: exited.connect(function() { handledExit = true })
  }

  Timer {
    id: launchCheck
    interval: 1
    repeat: false
    onTriggered: root.checkLaunches()
  }

  Command {
    id: probeProcess
    onExited: function(exitCode) { if (root.active && revision !== -1) root.installed = exitCode === 0 }
  }

  Command {
    id: nmProcess
    stdout: StdioCollector { id: nmOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || !current) return
      var parsed = exitCode === 0 ? Proton.parseActive(nmOut.text) : { ok: false }
      root.storeNm(parsed, Date.now())
      Qt.callLater(function() { root.observed() })
    }
  }

  Command {
    id: statusProcess
    stdout: StdioCollector { id: statusOut; waitForEnd: true }
    stderr: StdioCollector { id: statusErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || !current) return
      var parsed = exitCode === 0 ? Proton.parseStatus(statusOut.text) : { ok: false, state: "unknown" }
      root.storeCli(parsed, Date.now())
      if (exitCode !== 0 && Proton.accountFromError(statusErr.text) === "signed-out") root.account = "signed-out"
      Qt.callLater(function() { root.observed() })
    }
  }

  Command {
    id: infoProcess
    stdout: StdioCollector { id: infoOut; waitForEnd: true }
    stderr: StdioCollector { id: infoErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      root.account = exitCode === 0 ? Proton.parseAccount(infoOut.text) : Proton.accountFromError(infoErr.text + "\n" + infoOut.text)
    }
  }

  Command {
    id: actionProcess
    stdout: StdioCollector { id: actionOut; waitForEnd: true }
    stderr: StdioCollector { id: actionErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      var name = root.action
      var fallback = name === "connect" ? "Proton VPN connect failed" : "Proton VPN disconnect failed"
      var text = exitCode === 0 ? "" : Proton.errorMessage(actionErr.text + "\n" + actionOut.text, fallback)
      if (exitCode !== 0 && Proton.accountFromError(text) === "signed-out") root.account = "signed-out"
      root.finishAction(name, exitCode === 0, text)
    }
  }

  Command {
    id: configProcess
    stdout: StdioCollector { id: configOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      var value = exitCode === 0 ? Proton.parseKillSwitch(configOut.text) : ""
      Qt.callLater(function() { root.killSwitchRead(value) })
    }
  }

  Command {
    id: countriesProcess
    stdout: StdioCollector { id: countriesOut; waitForEnd: true }
    stderr: StdioCollector { id: countriesErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      var list = exitCode === 0 ? Proton.parseCountries(countriesOut.text) : []
      if (list.length > 0) root.countries = list
      else root.countriesError = Proton.errorMessage(countriesErr.text, "Could not load Proton VPN countries")
    }
  }

  Command {
    id: citiesProcess
    property string code: ""
    stdout: StdioCollector { id: citiesOut; waitForEnd: true }
    stderr: StdioCollector { id: citiesErr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      var list = exitCode === 0 ? Proton.parseCities(citiesOut.text) : []
      if (list.length > 0) root.setCities(code, list)
      else root.citiesError = Proton.errorMessage(citiesErr.text, "Could not load cities")
    }
  }

  Command {
    id: serversProcess
    stdout: StdioCollector { id: serversOut; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || revision === -1) return
      var parsed = exitCode === 0 ? Proton.parseServerIndex(serversOut.text) : { ok: false, servers: [] }
      if (parsed.ok) root.servers = parsed.servers
      else root.serversError = "Proton server list unavailable; search shows countries and loaded cities only"
    }
  }
}
