import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property bool active: true
  readonly property var traffic: trafficService.traffic
  TrafficService {
    id: trafficService
    profile: root.active && root.status.state === "connected" ? (root.status.currentProfile || "") : ""
  }
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
    actionProcess.command = ["omarchy-wireguard"].concat(args)
    actionProcess.running = true
  }

  function connectLocation(location) {
    if (!location || !location.id || status.state === "unknown") return
    runAction("Connecting", Model.connectArgs(location))
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

  Component.onCompleted: refresh()

  Timer {
    interval: (root.panelOpen || root.transitioning ? 1500 : root.closedRefreshIntervalSec * 1000)
    repeat: true
    running: root.active
    onTriggered: root.refresh()
  }

  Timer {
    interval: 1000
    repeat: true
    running: root.active
    onTriggered: root.expireStatus()
  }

  onActiveChanged: if (!active) {
    statusProcess.running = false
    listProcess.running = false
    actionProcess.running = false
    pickerProcess.running = false
    diagnosticsProcess.running = false
    clipboardProcess.running = false
    installProcess.running = false
    delayedRefresh.stop()
    handshakeFailureNotificationDelay.stop()
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
    stdout: StdioCollector { id: actionStdout; waitForEnd: true }
    stderr: StdioCollector { id: actionStderr; waitForEnd: true }
    onExited: function(exitCode) {
      if (!root.active) return
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
      delayedRefresh.restart()
    }
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
