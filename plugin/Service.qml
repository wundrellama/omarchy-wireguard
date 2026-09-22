import QtQuick
import Quickshell
import Quickshell.Io
import "Model.js" as Model

Item {
  id: root

  property var settings: ({})
  property string installScriptPath: ""
  property string currentUser: Quickshell.env("USER") || Quickshell.env("LOGNAME")
  property bool panelOpen: false
  property var status: ({ ok: false, installed: false, setupRequired: true, state: "disabled", locations: [], errors: [], importReview: {} })
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
  property bool replaceImport: false
  property string diagnosticsText: ""
  property var catalog: ({ ok: true, locations: [] })
  property var importPaths: []

  signal actionFinished(string action, bool success)

  function intSetting(name, fallback, min, max) {
    var value = settings && settings[name] !== undefined ? settings[name] : fallback
    var number = parseInt(String(value), 10)
    if (!isFinite(number)) number = fallback
    return Math.max(min, Math.min(max, number))
  }

  function refresh() {
    if (!statusProcess.running) {
      refreshing = true
      statusProcess.command = ["omarchy-wireguard", "status"]
      statusProcess.running = true
    }
    if (!listProcess.running && (panelOpen || !catalog.locations || catalog.locations.length === 0)) {
      listProcess.command = ["omarchy-wireguard", "list"]
      listProcess.running = true
    }
  }

  function runAction(name, args) {
    if (busy || actionProcess.running) return
    pendingAction = name
    actionMessage = name
    actionProcess.command = ["omarchy-wireguard"].concat(args)
    actionProcess.running = true
  }

  function connectLocation(location) {
    if (!location || !location.id) return
    runAction("Connecting", ["connect", String(location.id)])
  }

  function disconnect() { runAction("Disconnecting", ["disconnect"]) }
  function retry() { runAction("Retrying", ["retry"]) }
  function pauseTenMinutes() { runAction("Pausing for 10 minutes", ["pause", "600"]) }

  function chooseImport(replace, directory) {
    if (pickerProcess.running || busy) return
    replaceImport = replace === true
    pickerMode = directory === true ? "directory" : "files"
    pickerProcess.command = directory === true
      ? ["omarchy-file-select", "--title", "Import WireGuard profile directory", "--directory"]
      : ["omarchy-file-select", "--title", "Import WireGuard profiles", "--multiple", "--extensions", "zip conf"]
    pickerProcess.running = true
  }

  function submitImportReview(locations) {
    if (!importPaths || importPaths.length === 0 || !locations || typeof locations !== "object") return
    runAction("Importing reviewed profiles", ["import"].concat(importPaths).concat(["--locations", JSON.stringify(locations)]))
  }

  function installBackend() {
    if (installProcess.running || !installScriptPath || !currentUser) return
    actionMessage = "Installing backend"
    installProcess.operation = "install"
    installProcess.command = ["pkexec", installScriptPath, currentUser]
    installProcess.running = true
  }

  function uninstallBackend() {
    if (installProcess.running || !currentUser) return
    actionMessage = "Uninstalling backend"
    installProcess.operation = "uninstall"
    installProcess.command = ["pkexec", "/usr/lib/omarchy-wireguard/uninstall-backend", currentUser]
    installProcess.running = true
  }

  function openGenerator() {
    // TorGuard assumption: this optional shortcut opens TorGuard's profile generator.
    Quickshell.execDetached(["omarchy-launch-browser", "https://torguard.net/tgconf.php?action=vpn-wireguardconfig"])
  }

  function copyDiagnostics() {
    if (diagnosticsProcess.running || clipboardProcess.running) return
    diagnosticsText = ""
    diagnosticsProcess.command = ["omarchy-wireguard", "diagnostics"]
    diagnosticsProcess.running = true
  }

  function notify(summary, body, urgency) {
    Quickshell.execDetached(["notify-send", "--app-name", "WireGuard", "--urgency", urgency || "normal", summary, body || ""])
  }

  function applyStatus(raw) {
    var next = Model.parseStatus(raw)
    if (!next.ok) {
      lastError = next.message + (next.reason ? ": " + next.reason : "")
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
      if (previousPaused && !merged.paused) notify("WireGuard pause expired", "VPN protection resumed", "normal")
    }
    previousState = merged.state
    previousPaused = merged.paused
    sawFirstStatus = true
    status = merged
    lastError = ""
  }

  function markCliUnavailable(message) {
    refreshing = false
    lastError = message || "WireGuard CLI is not available"
    var next = ({})
    for (var key in status) next[key] = status[key]
    next.installed = false
    next.setupRequired = true
    next.state = "disabled"
    next.reason = lastError
    status = next
  }

  function applyActionOutput(raw) {
    var value
    try {
      value = JSON.parse(String(raw || ""))
    } catch (error) {
      return
    }
    if (!value || typeof value !== "object") return
    if (value.ok === false) {
      actionError = String((value.error && value.error.message) || "Backend request failed")
      return
    }
    if (value.result && typeof value.result === "object") value = value.result
    var review = value.import_review || value.importReview || value.review
    if (!review && Array.isArray(value.review_required)) review = {
      ambiguous: value.review_required.length > 0,
      message: value.message || "Location review is required",
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
    running: true
    onTriggered: root.refresh()
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
    property bool handledExit: false
    stdout: StdioCollector { id: statusStdout; waitForEnd: true }
    stderr: StdioCollector { id: statusStderr; waitForEnd: true }
    onRunningChanged: {
      if (running) handledExit = false
      else statusLaunchCheck.restart()
    }
    onExited: function(exitCode) {
      handledExit = true
      root.refreshing = false
      if (exitCode === 0) root.applyStatus(statusStdout.text)
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
      var action = root.pendingAction
      root.pendingAction = ""
      root.actionMessage = ""
      if (exitCode !== 0) root.actionError = String(actionStderr.text || actionStdout.text || "WireGuard action failed").trim()
      else {
        root.actionError = ""
        if (String(actionStdout.text || "").trim().charAt(0) === "{") root.applyActionOutput(actionStdout.text)
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
      if (exitCode === 1) return
      if (exitCode !== 0) {
        root.actionError = String(pickerStderr.text || "File chooser failed").trim()
        return
      }
      var paths = String(pickerStdout.text || "").split("\n").filter(function(path) { return path !== "" })
      if (paths.length === 0) return
      root.importPaths = paths
      root.runAction("Importing profiles", ["import"].concat(paths))
    }
  }

  Process {
    id: diagnosticsProcess
    stdout: StdioCollector { id: diagnosticsStdout; waitForEnd: true }
    stderr: StdioCollector { id: diagnosticsStderr; waitForEnd: true }
    onExited: function(exitCode) {
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
