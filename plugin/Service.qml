import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model
import "Proton.js" as Proton

Item {
  id: root

  property bool active: true
  readonly property var traffic: trafficService.traffic
  TrafficService {
    id: trafficService
    profile: root.active ? Proton.trafficProfile(root.status, root.shield) : ""
  }
  ProtonService {
    id: protonService
    active: root.active
    panelOpen: root.panelOpen
    phase: root.switchPhase
  }
  // Proton adapter: user-session CLI only; nothing here reaches the root backend.
  readonly property var proton: protonService
  readonly property var protonStatus: protonService.status
  readonly property var shield: Proton.shield(status, protonService.status, disconnectRecovery, wireGuardAbsent())
  property string protonQuery: ""
  readonly property var filteredCountries: Proton.filterCountries(protonService.countries, protonQuery)
  // One live Proton search: countries, cities and servers from the cached index.
  readonly property var protonResults: Proton.searchProton(protonQuery, protonService.countries, protonService.cities, protonService.servers, 30)
  readonly property string protonServersError: protonService.serversError
  // Last connection: a validated choice descriptor read from and written to
  // last_connection.py. pendingConnection is recorded only on success.
  readonly property string lastConnectionHelper: decodeURIComponent(String(Qt.resolvedUrl("last_connection.py")).replace(/^file:\/\//, ""))
  property var lastConnection: null
  property var pendingConnection: null
  property var queuedConnection: null
  readonly property var quickAction: Proton.quickAction({ wg: status, recovery: disconnectRecovery, wgAbsent: wireGuardAbsent(), proton: protonService.status, switching: switchPhase !== "" || !!switchRequest, busy: busy, protonBusy: protonService.busy, record: lastConnection, locations: status.locations || [], mru: catalog.mru || [], countries: protonService.countries })
  readonly property var protonCities: protonService.cities
  readonly property string protonCountriesError: protonService.countriesError
  readonly property string protonCitiesError: protonService.citiesError
  // One transition at a time: {target, choice|location, label} awaiting inline confirmation.
  property var switchRequest: null
  property var switchTarget: null
  property string switchPhase: ""
  property double switchStartedAt: 0
  property double wgReleasedAfter: 0
  property double protonReleasedAfter: 0
  property double lastStatusAt: 0
  property int statusRevision: 0
  property bool disconnectRecovery: false
  property var settings: ({})
  property string installScriptPath: ""
  property string currentUser: Quickshell.env("USER") || Quickshell.env("LOGNAME")
  property bool panelOpen: false
  property var status: Model.unknownStatus("Checking status")
  property string lastError: ""
  property string actionError: ""
  property string actionMessage: ""
  property bool refreshing: false
  property string query: ""
  readonly property var filteredLocations: Model.filterLocations(status.locations || [], query)
  readonly property bool transitioning: status.state === "connecting"
  readonly property bool busy: actionProcess.running || pickerProcess.running || diagnosticsProcess.running || installProcess.running
    || protonService.busy || switchPhase !== ""
  readonly property int closedRefreshIntervalSec: intSetting("closedRefreshIntervalSec", 30, 15, 300)
  property string previousState: ""
  property bool previousPaused: false
  property bool sawFirstStatus: false
  property bool failureNotificationShown: false
  property bool handshakeFailureConfirmationPending: false
  property string pendingAction: ""
  property string pickerMode: ""

  property string diagnosticsText: ""
  property var catalog: ({ ok: true, locations: [] })
  property var importPaths: []

  signal actionFinished(string action, bool success)
  signal importSelectionFinished()

  function intSetting(name, fallback, min, max) {
    var value = settings && settings[name] !== undefined ? settings[name] : fallback
    var number = parseInt(String(value), 10)
    if (!isFinite(number)) number = fallback
    return Math.max(min, Math.min(max, number))
  }

  function refresh() {
    if (!active || actionProcess.running || installProcess.running) return
    if (!statusProcess.running) {
      refreshing = true
      statusProcess.startedAt = Date.now()
      statusProcess.revision = statusRevision
      statusProcess.command = ["omarchy-wireguard", "status"]
      statusProcess.running = true
    }
    if (!listProcess.running && (panelOpen || !catalog.locations || catalog.locations.length === 0)) {
      listProcess.command = ["omarchy-wireguard", "list"]
      listProcess.running = true
    }
  }

  function runAction(name, args) {
    if (!active || busy || actionProcess.running) return
    if (status.state === "unknown" && args[0] !== "disconnect") return
    pendingAction = name
    actionMessage = name
    statusRevision++
    markCliUnavailable("Action in progress; awaiting status")
    actionProcess.startedAt = Date.now()
    actionProcess.abandoned = false
    actionProcess.command = ["omarchy-wireguard"].concat(args)
    actionProcess.running = true
  }

  // A hung CLI action is abandoned after 120 s (the Proton connect bound) so
  // it cannot wedge the panel; its late exit, if any, is ignored.
  function expireAction() {
    if (!actionProcess.running || Date.now() - actionProcess.startedAt <= 120000) return
    var action = pendingAction
    actionProcess.abandoned = true
    actionProcess.running = false
    pendingAction = ""
    actionMessage = ""
    statusRevision++
    markCliUnavailable("Action timed out; connection is unknown")
    if (switchPhase === "wg-disconnect") abortSwitch("WireGuard disconnect timed out; Proton VPN was not started")
    else actionError = "WireGuard command timed out; status is unknown until the next check"
    actionFinished(action, false)
    delayedRefresh.restart()
  }

  function connectLocation(location) {
    if (!location || !location.id || status.state === "unknown" || busy) return
    var proton = protonService.status || {}
    if (proton.state === "connected" || proton.state === "connecting" || proton.state === "disconnecting") {
      switchRequest = { target: "wireguard", location: location, label: location.label || location.city || location.id }
      return
    }
    if (proton.state === "unknown" && proton.installed !== false) {
      actionError = "Proton VPN status is unknown; wait for it to refresh before connecting WireGuard"
      return
    }
    runAction("Connecting", Model.connectArgs(location))
    if (actionProcess.running) pendingConnection = Proton.lastFromLocation(location)
  }

  // The quick button: reconnect the last choice or disconnect the active VPN
  // through the normal paths. Disabled and hidden states do nothing.
  function quickConnect() {
    var action = quickAction
    if (!active || busy || !action || !action.enabled) return
    if (action.mode === "disconnect" && action.vpn === "wireguard") disconnect()
    else if (action.mode === "disconnect" && action.vpn === "proton") disconnectProton()
    else if (action.mode === "connect" && action.vpn === "wireguard") connectLocation(action.target.location)
    else if (action.mode === "connect" && action.vpn === "proton") connectProton(action.target.choice)
  }

  function loadLastConnection() {
    if (!active || lastConnectionReader.running) return
    lastConnectionReader.startedAt = Date.now()
    lastConnectionReader.command = ["python3", "-B", lastConnectionHelper, "read"]
    lastConnectionReader.running = true
  }

  // The reader is bounded like the other commands; a hung read loses history only.
  function expireLastConnection() {
    if (lastConnectionReader.running && Date.now() - lastConnectionReader.startedAt > 10000)
      lastConnectionReader.running = false
  }

  function applyLastConnection(raw) { lastConnection = Proton.parseLastConnection(raw) }

  // One writer at a time. A record that arrives during a write is kept (the
  // latest wins) and written when the current write exits.
  function recordConnection(record) {
    pendingConnection = null
    if (!active || !record) return
    lastConnection = record
    if (lastConnectionWriter.running) { queuedConnection = record; return }
    lastConnectionWriter.command = ["python3", "-B", lastConnectionHelper, "write", JSON.stringify(record)]
    lastConnectionWriter.running = true
  }

  function lastConnectionWritten() {
    var next = queuedConnection
    queuedConnection = null
    if (!active || !next || lastConnectionWriter.running) return
    lastConnectionWriter.command = ["python3", "-B", lastConnectionHelper, "write", JSON.stringify(next)]
    lastConnectionWriter.running = true
  }

  // WireGuard is recorded when a status poll shows the chosen location connected.
  // A poll that shows the attempt ended (disabled, failed, ...) clears it, so
  // a later connection made outside the panel is never recorded.
  function checkPendingConnection() {
    var pending = pendingConnection
    if (!pending || pending.kind !== "wireguard") return
    if (status.state !== "connected") {
      if (status.state !== "connecting" && status.state !== "unknown") pendingConnection = null
      return
    }
    var locations = status.locations || []
    for (var i = 0; i < locations.length; i++) {
      if (locations[i].id !== pending.value) continue
      if (locations[i].current === true) recordConnection(pending)
      else pendingConnection = null
      return
    }
    pendingConnection = null
  }

  // The backend CLI reports this when its socket is absent; no WireGuard intent can exist.
  function wireGuardAbsent() {
    return status.state === "unknown" && /not installed or running/.test(lastError) && !disconnectRecovery
  }

  function connectProton(choice) {
    if (!active || busy) return
    if (!Proton.connectArgs(choice)) { actionError = "Invalid Proton VPN selection"; return }
    if (Proton.wireGuardActive(status, disconnectRecovery)) {
      pendingConnection = null
      switchRequest = { target: "proton", choice: choice, label: Proton.choiceLabel(choice) }
      return
    }
    if (status.state === "unknown" && !wireGuardAbsent()) {
      actionError = "WireGuard status is unknown; refresh before connecting Proton VPN"
      return
    }
    var protonState = (protonService.status || {}).state
    if (protonState !== "connected" && protonState !== "disconnected") {
      actionError = "Proton VPN is " + (protonState || "unknown") + "; wait for its status before connecting"
      return
    }
    actionError = ""
    if (!protonService.connect(choice)) actionError = "Proton VPN is busy or unavailable"
    else pendingConnection = Proton.lastFromChoice(choice)
  }

  function disconnectProton() {
    if (!active || busy) return
    actionError = ""
    if (!protonService.disconnect()) actionError = "Proton VPN is busy or unavailable"
  }

  function protonSignIn() { if (active) protonService.signIn() }
  function loadProtonCountries(force) { if (active) { protonService.loadCountries(force === true); protonService.loadServers(force === true) } }
  function loadProtonCities(code) { if (active) protonService.loadCities(code) }

  function cancelSwitch() { switchRequest = null }

  function abortSwitch(message) {
    pendingConnection = null
    switchPhase = ""
    switchTarget = null
    actionMessage = ""
    actionError = message
  }

  // Confirmed switch. WireGuard -> Proton: disconnect WireGuard (removes its
  // fail-closed firewall), wait for a newer status poll showing disabled,
  // then connect Proton. Proton -> WireGuard: refuse unless Proton's kill
  // switch is off, disconnect Proton, wait for Disconnected, then connect.
  function confirmSwitch() {
    var request = switchRequest
    if (!active || !request || busy) return
    switchRequest = null
    switchStartedAt = Date.now()
    actionError = ""
    switchTarget = request
    if (request.target === "proton") {
      runAction("Switching to Proton VPN", ["disconnect"])
      if (!actionProcess.running) { abortSwitch("Could not start the WireGuard disconnect; Proton VPN was not started"); return }
      switchPhase = "wg-disconnect"
      return
    }
    switchPhase = "ks-check"
    actionMessage = "Checking the Proton VPN kill switch"
    if (!protonService.readKillSwitch()) abortSwitch("Could not read the Proton VPN kill switch setting; WireGuard was not started")
  }

  function wireGuardActionDone(success) {
    if (!success && pendingConnection && pendingConnection.kind === "wireguard") pendingConnection = null
    if (switchPhase !== "wg-disconnect") return
    if (!success) {
      abortSwitch("WireGuard disconnect failed; Proton VPN was not started: " + (actionError || "unknown error"))
      return
    }
    wgReleasedAfter = Date.now()
    switchPhase = "wg-wait"
    actionMessage = "Waiting for WireGuard to report disabled"
  }

  function protonKillSwitchRead(value) {
    if (switchPhase !== "ks-check") return
    if (value === "off") {
      switchPhase = "proton-disconnect"
      actionMessage = "Disconnecting Proton VPN"
      if (!protonService.disconnect()) abortSwitch("Could not disconnect Proton VPN; WireGuard was not started")
    } else if (!value) abortSwitch("Could not read the Proton VPN kill switch setting; WireGuard was not started")
    else abortSwitch("Proton VPN kill switch is " + value + ". Disconnect Proton VPN or set its kill switch to off, then connect WireGuard.")
  }

  function protonActionDone(name, success, message) {
    if (name === "connect" && pendingConnection && pendingConnection.kind !== "wireguard") {
      if (success && (switchPhase === "" || switchPhase === "proton-connect")) recordConnection(pendingConnection)
      else pendingConnection = null
    }
    if (switchPhase === "proton-connect" && name === "connect") {
      switchPhase = ""
      switchTarget = null
      actionMessage = ""
      actionError = success ? "" : "Proton VPN connect failed: " + message
    } else if (switchPhase === "proton-disconnect" && name === "disconnect") {
      if (!success) {
        abortSwitch("Proton VPN disconnect failed; WireGuard was not started: " + message)
        return
      }
      protonReleasedAfter = Date.now()
      switchPhase = "proton-wait"
      actionMessage = "Waiting for Proton VPN to report Disconnected"
      protonService.refresh()
    }
  }

  function protonObserved() { if (switchPhase === "proton-wait") Qt.callLater(advanceSwitch) }

  function protonReleased() {
    var nm = protonService.nm || {}
    var cli = protonService.cli || {}
    return nm.ok === true && nm.match === "none" && nm.at > protonReleasedAfter
      && cli.ok === true && cli.state === "disconnected" && cli.at > protonReleasedAfter
  }

  function advanceSwitch() {
    if (!active || !switchTarget) return
    if (switchPhase === "wg-wait" && Proton.wireGuardReleased(status, lastStatusAt, wgReleasedAfter)) {
      switchPhase = "proton-connect"
      actionMessage = "Connecting Proton VPN"
      if (!protonService.connect(switchTarget.choice)) abortSwitch("Could not start Proton VPN; WireGuard is disconnected")
      else pendingConnection = Proton.lastFromChoice(switchTarget.choice)
    } else if (switchPhase === "proton-wait" && protonReleased()) {
      var location = switchTarget.location
      switchPhase = ""
      switchTarget = null
      runAction("Connecting", Model.connectArgs(location))
      if (!actionProcess.running) actionError = "Could not start WireGuard; Proton VPN is disconnected"
      else pendingConnection = Proton.lastFromLocation(location)
    }
  }

  // Whole-transition bound, above the 120 s Proton connect timeout. Late
  // results are discarded because every step checks the current switchPhase.
  function checkSwitchDeadline() {
    if (switchPhase !== "" && Date.now() - switchStartedAt > 150000) {
      switchRequest = null
      abortSwitch("VPN switch timed out; neither VPN is started automatically. Check status before connecting.")
    } else if (switchPhase === "wg-wait" && Date.now() - wgReleasedAfter > 30000)
      abortSwitch("WireGuard did not report disabled; Proton VPN was not started")
    else if (switchPhase === "proton-wait" && Date.now() - protonReleasedAfter > 30000)
      abortSwitch("Proton VPN did not report Disconnected; WireGuard was not started")
  }

  function disconnect() { if (status.state !== "unknown" || disconnectRecovery) runAction("Disconnecting", ["disconnect"]) }
  function retry() { runAction("Retrying", ["retry"]) }


  function chooseImport(directory) {
    if (!active || status.state === "unknown" || pickerProcess.running || busy) return
    pickerMode = directory === true ? "directory" : "files"
    pickerProcess.command = directory === true
      ? ["omarchy-file-select", "--title", "Import WireGuard profile directory", "--directory"]
      : ["omarchy-file-select", "--title", "Import WireGuard profiles", "--multiple", "--extensions", "zip conf"]
    pickerProcess.running = true
  }

  function submitImportReview(labels) {
    if (!importPaths || importPaths.length === 0 || !Model.reviewComplete(status.importReview.candidates, labels)) return
    runAction("Importing reviewed profiles", Model.importReviewArgs(importPaths, labels))
  }

  function installBackend() {
    if (!active || busy || installProcess.running || !installScriptPath || !currentUser) return
    actionMessage = "Installing backend"
    installProcess.operation = "install"
    installProcess.command = ["pkexec", installScriptPath, currentUser]
    installProcess.running = true
  }

  function uninstallBackend() {
    if (!active || status.state === "unknown" || installProcess.running || !currentUser) return
    actionMessage = "Uninstalling backend"
    installProcess.operation = "uninstall"
    installProcess.command = ["pkexec", "/usr/lib/omarchy-wireguard/uninstall-backend", currentUser]
    installProcess.running = true
  }

  function openGenerator() {
    if (!active) return
    // TorGuard assumption: this optional shortcut opens TorGuard's profile generator.
    Quickshell.execDetached(["omarchy-launch-browser", "https://torguard.net/tgconf.php?action=vpn-wireguardconfig"])
  }

  function copyDiagnostics() {
    if (!active || diagnosticsProcess.running || clipboardProcess.running) return
    diagnosticsText = ""
    diagnosticsProcess.command = ["omarchy-wireguard", "diagnostics"]
    diagnosticsProcess.running = true
  }

  function notify(summary, body, urgency) {
    if (!active) return
    Quickshell.execDetached(["omarchy-notification-send", "--app-name", "WireGuard", "--urgency", urgency || "normal", summary, body || ""])
  }

  function applyStatus(raw) {
    var next = Model.parseStatus(raw)
    if (!next.ok) {
      markCliUnavailable(next.message)
      return
    }
    var merged = Model.mergeStatusCatalog(next, catalog)
    if (status.importReview && status.importReview.ambiguous
        && (!merged.importReview || !merged.importReview.ambiguous)) {
      merged.importReview = status.importReview
    }
    if (sawFirstStatus && !next.backendNotifies) {
      if (merged.state === "failed") {
        if (Model.isHandshakeOnlyFailure(merged)) {
          if (previousState !== "failed" && !failureNotificationShown)
            handshakeFailureNotificationDelay.restart()
          if (handshakeFailureConfirmationPending) {
            handshakeFailureConfirmationPending = false
            failureNotificationShown = true
            notify("WireGuard connection failed", merged.reason, "critical")
          }
        } else {
          handshakeFailureNotificationDelay.stop()
          handshakeFailureConfirmationPending = false
          if (!failureNotificationShown) {
            failureNotificationShown = true
            notify("WireGuard connection failed", merged.reason, "critical")
          }
        }
      } else {
        handshakeFailureNotificationDelay.stop()
        handshakeFailureConfirmationPending = false
        if (merged.state === "connected" && failureNotificationShown)
          notify("WireGuard recovered", merged.location, "normal")
        if (merged.state === "connected" || merged.state === "disabled" || merged.state === "paused")
          failureNotificationShown = false
      }

    }
    previousState = merged.state
    previousPaused = merged.paused
    sawFirstStatus = true
    lastStatusAt = Date.now()
    disconnectRecovery = merged.enabled === true || merged.state === "connected"
    status = merged
    lastError = ""
    checkPendingConnection()
  }

  function markCliUnavailable(message) {
    refreshing = false
    lastError = message || "WireGuard CLI is not available"
    var next = Model.mergeStatusCatalog(Model.unknownStatus(lastError), catalog)
    next.importReview = status.importReview || {}
    status = next
  }

  function expireStatus() {
    if (statusProcess.running && Date.now() - statusProcess.startedAt > 10000) {
      statusRevision++
      statusProcess.running = false
      markCliUnavailable("Status request timed out; connection is unknown")
    }
    if (lastStatusAt && Date.now() - lastStatusAt > Math.max(10000, closedRefreshIntervalSec * 2000))
      markCliUnavailable("Status is stale; connection is unknown")
  }

  function applyPoll(raw, startedAt, revision) {
    if (!active || revision !== statusRevision) return
    if (Date.now() - startedAt > 10000) {
      markCliUnavailable("Stale status response ignored")
      return
    }
    applyStatus(raw)
    if (switchPhase === "wg-wait") Qt.callLater(advanceSwitch)
  }

  function applyActionOutput(raw) {
    var value
    try {
      value = JSON.parse(String(raw || ""))
    } catch (error) {
      markCliUnavailable("Invalid action response")
      return
    }
    if (!value || typeof value !== "object") return
    if (value.ok === false) {
      actionError = String((value.error && value.error.message) || "Backend request failed")
      markCliUnavailable("Action rejected; refresh required")
      return
    }
    if (value.result && typeof value.result === "object") value = value.result
    var review = value.import_review || value.importReview || value.review
    if (!review && Array.isArray(value.review_required)) review = {
      ambiguous: value.review_required.length > 0,
      message: value.message || "Display labels are required",
      candidates: value.review_required
    }
    var errors = value.errors || value.problems
    if (review || errors) {
      var next = ({})
      for (var key in status) next[key] = status[key]
      if (review) next.importReview = {
        ambiguous: review.ambiguous === true,
        message: String(review.message || review.reason || ""),
        candidates: Array.isArray(review.candidates) ? review.candidates : []
      }
      if (errors) next.errors = Array.isArray(errors) ? errors : [errors]
      status = next
      return
    }
    if (value.imported === true) {
      var importedStatus = ({})
      for (var importedKey in status) importedStatus[importedKey] = status[importedKey]
      importedStatus.importReview = { ambiguous: false, message: "", candidates: [] }
      importedStatus.errors = []
      status = importedStatus
      catalog = { ok: true, locations: [] }
      return
    }
    applyStatus(raw)
  }

  Component.onCompleted: { refresh(); loadLastConnection() }

  Timer {
    interval: (root.panelOpen || root.transitioning || root.switchPhase !== "" ? 1500 : root.closedRefreshIntervalSec * 1000)
    repeat: true
    running: root.active
    onTriggered: root.refresh()
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.active
    onTriggered: { root.expireStatus(); root.expireAction(); root.expireLastConnection(); root.checkSwitchDeadline() }
  }

  Connections {
    target: protonService
    function onActionDone(action, success, message) { root.protonActionDone(action, success, message) }
    function onKillSwitchRead(value) { root.protonKillSwitchRead(value) }
    function onObserved() { root.protonObserved() }
  }

  onActiveChanged: if (!active) {
    statusProcess.running = false
    listProcess.running = false
    actionProcess.running = false
    pickerProcess.running = false
    diagnosticsProcess.running = false
    clipboardProcess.running = false
    installProcess.running = false
    lastConnectionReader.running = false
    delayedRefresh.stop()
    handshakeFailureNotificationDelay.stop()
    switchRequest = null
    switchTarget = null
    switchPhase = ""
  }

  Timer {
    id: delayedRefresh
    interval: 500
    repeat: false
    onTriggered: root.refresh()
  }

  Timer {
    id: handshakeFailureNotificationDelay
    interval: 15000
    repeat: false
    onTriggered: {
      root.handshakeFailureConfirmationPending = true
      root.refresh()
    }
  }

  Process {
    id: statusProcess
    property double startedAt: 0
    property int revision: 0
    property bool handledExit: false
    stdout: StdioCollector { id: statusStdout; waitForEnd: true }
    stderr: StdioCollector { id: statusStderr; waitForEnd: true }
    onRunningChanged: {
      if (running) handledExit = false
      else statusLaunchCheck.restart()
    }
    onExited: function(exitCode) {
      handledExit = true
      if (!root.active) return
      root.refreshing = false
      if (exitCode === 0) root.applyPoll(statusStdout.text, startedAt, revision)
      else {
        var error = String(statusStderr.text || statusStdout.text || "WireGuard backend unavailable").trim()
        root.markCliUnavailable(error)
        if (root.sawFirstStatus && root.previousState !== "failed") root.notify("WireGuard status failed", error, "critical")
        root.previousState = "failed"
      }
    }
  }

  Timer {
    id: statusLaunchCheck
    interval: 1
    repeat: false
    onTriggered: if (!statusProcess.running && !statusProcess.handledExit) root.markCliUnavailable("Could not launch omarchy-wireguard")
  }

  Process {
    id: listProcess
    stdout: StdioCollector { id: listStdout; waitForEnd: true }
    stderr: StdioCollector { id: listStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active) return
      if (exitCode !== 0) {
        root.lastError = String(listStderr.text || listStdout.text || "Could not list WireGuard locations").trim()
        return
      }
      var parsed = Model.parseCatalog(listStdout.text)
      if (!parsed.ok) {
        root.lastError = parsed.message
        return
      }
      root.catalog = parsed
      root.status = Model.mergeStatusCatalog(root.status, parsed)
    }
  }

  Process {
    id: actionProcess
    property double startedAt: 0
    property bool abandoned: false
    stdout: StdioCollector { id: actionStdout; waitForEnd: true }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active || abandoned) return
      var action = root.pendingAction
      root.pendingAction = ""
      root.actionMessage = ""
      if (exitCode !== 0) {
        root.actionError = String(actionStderr.text || actionStdout.text || "WireGuard action failed").trim()
        root.markCliUnavailable("Action failed; refresh required")
      }
      else {
        root.actionError = ""
        root.applyActionOutput(actionStdout.text)
      }
      root.actionFinished(action, exitCode === 0)
      root.wireGuardActionDone(exitCode === 0)
      delayedRefresh.restart()
    }
  }

  Process {
    id: lastConnectionReader
    property double startedAt: 0
    stdout: StdioCollector { id: lastConnectionOut; waitForEnd: true }
    onExited: function(exitCode) { if (root.active) root.applyLastConnection(exitCode === 0 ? lastConnectionOut.text : "") }
  }

  // A failed write only loses history. Quickshell emits exited before
  // runningChanged, so the queued write starts on the next turn.
  Process {
    id: lastConnectionWriter
    onExited: Qt.callLater(root.lastConnectionWritten)
  }

  Process {
    id: pickerProcess
    stdout: StdioCollector { id: pickerStdout; waitForEnd: true }
    stderr: StdioCollector { id: pickerStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active) return
      if (exitCode === 1) return
      if (exitCode !== 0) {
        root.actionError = String(pickerStderr.text || "File chooser failed").trim()
        root.importSelectionFinished()
        return
      }
      var paths = String(pickerStdout.text || "").split("\n").filter(function(path) { return path !== "" })
      if (paths.length === 0) return
      // Quickshell emits exited before runningChanged. Starting synchronously
      // here would be silently rejected because busy still includes the picker.
      Qt.callLater(function() {
        if (!root.active) return
        root.importPaths = paths
        if (root.busy || root.status.state === "unknown")
          root.actionError = "Cannot import while busy or status is unknown; refresh and try again"
        else
          root.runAction("Importing profiles", ["import"].concat(paths))
        root.importSelectionFinished()
      })
    }
  }

  Process {
    id: diagnosticsProcess
    stdout: StdioCollector { id: diagnosticsStdout; waitForEnd: true }
    stderr: StdioCollector { id: diagnosticsStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active) return
      if (exitCode !== 0) {
        root.actionError = String(diagnosticsStderr.text || "Could not collect diagnostics").trim()
        return
      }
      root.actionError = ""
      root.diagnosticsText = String(diagnosticsStdout.text || "")
      clipboardProcess.command = ["wl-copy"]
      clipboardProcess.running = true
    }
  }

  Process {
    id: clipboardProcess
    stdinEnabled: true
    onStarted: {
      write(root.diagnosticsText)
      stdinEnabled = false
    }
    onExited: function(exitCode) {
      root.diagnosticsText = ""
      if (exitCode === 0) root.actionMessage = "Diagnostics copied"
      else root.actionError = "Could not copy diagnostics"
    }
  }

  Process {
    id: installProcess
    property bool handledExit: false
    property string operation: ""
    stdout: StdioCollector { id: installStdout; waitForEnd: true }
    stderr: StdioCollector { id: installStderr; waitForEnd: true }
    onRunningChanged: {
      if (running) handledExit = false
      else installLaunchCheck.restart()
    }
    onExited: function(exitCode) {
      handledExit = true
      root.actionMessage = ""
      if (exitCode !== 0) root.actionError = String(installStderr.text || installStdout.text || "Backend maintenance failed").trim()
      else {
        root.actionError = ""
        root.actionMessage = operation === "uninstall" ? "Backend uninstalled" : "Backend installed"
      }
      delayedRefresh.restart()
    }
  }

  Timer {
    id: installLaunchCheck
    interval: 1
    repeat: false
    onTriggered: if (!installProcess.running && !installProcess.handledExit) {
      root.actionMessage = ""
      root.actionError = "Could not launch backend maintenance"
    }
  }
}
