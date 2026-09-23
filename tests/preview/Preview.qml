import QtQuick
import Quickshell.Io
import "../../plugin" as Vpn
import "../../plugin/Model.js" as Model

// Explicit visual-test fixture. Never delegates any action to the real backend.
Vpn.BarWidget {
  id: preview
  moduleName: "wundrellama.wireguard-preview"
  ipcTarget: moduleName
  serviceOverride: fixture

  QtObject {
    id: fixture
    property var settings: ({})
    property bool active: false
    property string currentUser: ""
    property bool panelOpen: false
    property string query: ""
    property bool busy: false
    property string installScriptPath: ""
    property string lastError: ""
    property string actionError: ""
    property string actionMessage: "PREVIEW ONLY — synthetic profiles; no networking commands."
    property string lastAction: ""
    property var importPaths: ["/preview/example.conf"]
    property var status: ({state: "unknown", installed: true, locations: [], errors: []})
    readonly property bool transitioning: status.state === "connecting"
    readonly property var filteredLocations: Model.filterLocations(status.locations || [], query)
    signal actionFinished(string action, bool success)

    readonly property var catalog: Model.parseCatalog(JSON.stringify({ok: true, result: {
      profiles: [
        {id: "preview-home", label: "Example home exit", role: "internet-exit", source_name: "home.conf", country: "", city: ""},
        {id: "preview-travel", label: "Example travel exit with a deliberately long profile name", role: "internet-exit", source_name: "travel.conf", country: "Japan", city: "Tokyo"}
      ],
      mru: ["preview-home"]
    }}))

    function scenario(mode) {
      var selected = mode !== "disabled" && mode !== "unknown"
      var raw = {mode: mode, enabled: selected, target: selected ? "profile:preview-home" : null,
        current_profile: mode === "connected" ? "preview-home" : null,
        current: mode === "connected" ? {id: "preview-home", label: "Example home exit", role: "internet-exit"} : null,
        target_profile: selected ? {id: "preview-home", label: "Example home exit", role: "internet-exit"} : null,
        last_error: mode === "failed" ? "Synthetic handshake failure — no real tunnel was attempted" : null}
      var next = Model.mergeStatusCatalog(Model.parseStatus(JSON.stringify({ok: true, result: raw})), catalog)
      if (next.reason) next.reason = "PREVIEW ONLY — " + next.reason
      status = next
      query = ""
      lastAction = ""
      lastError = ""
      actionError = ""
      actionMessage = "PREVIEW ONLY — synthetic profiles; no networking commands."
    }

    function refresh() {}
    function record(action) {
      lastAction = action
      actionMessage = "PREVIEW ONLY — recorded " + action + "; nothing executed."
      actionFinished(action, true)
    }
    function connectLocation(location) { record("connect:" + location.id) }
    function disconnect() { record("disconnect") }
    function retry() { record("retry") }

    function copyDiagnostics() { record("diagnostics") }
    function installBackend() { record("install refused in preview") }
    function uninstallBackend() { record("uninstall refused in preview") }
    function openGenerator() { record("browser refused in preview") }
    function chooseImport() {
      var next = Object.assign({}, status)
      next.importReview = {ambiguous: true, message: "Give this synthetic profile a display name. Imports only add profiles.", candidates: ["example.conf"]}
      status = next
      record("import review")
    }
    function submitImportReview(labels) { record("labels:" + JSON.stringify(labels)) }
  }

  IpcHandler {
    target: "wundrellama.wireguard-preview-controls"
    function scenario(mode: string): string { fixture.scenario(mode); return "ok" }
    function review(): string { fixture.chooseImport(); return "ok" }
    function label(value: string): string { preview.setReviewValue("example.conf", value); return "ok" }
    function submit(): string { preview.submitReview(); return fixture.lastAction }
    function search(value: string): string { fixture.query = value; return "ok" }
    function activate(index: int): string {
      preview.selectedIndex = index
      preview.activateSelected()
      return fixture.lastAction
    }
    function inspect(): string {
      return JSON.stringify({status: fixture.status, query: fixture.query, lastAction: fixture.lastAction, opened: preview.opened, selectedIndex: preview.selectedIndex, reviewValues: preview.reviewValues})
    }
  }

  Component.onCompleted: fixture.scenario("disabled")
}
