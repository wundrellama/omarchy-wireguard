import QtQuick
import Quickshell.Io
import "../../plugin" as Vpn
import "../../plugin/Model.js" as Model
import "../../plugin/Proton.js" as Proton

// Explicit visual-test fixture. Never delegates any action to the real backend.
Vpn.BarWidget {
  id: preview
  moduleName: "wundrellama.wireguard-preview"
  ipcTarget: moduleName
  serviceOverride: fixture

  QtObject {
    id: fixture
    property var settings: ({})
    // Deliberately synthetic: no sampler runs when serviceOverride is injected.
    readonly property var traffic: shield.state === "connected"
      ? ({rx: 15728640, tx: 2097152, down: 131072, up: 16384}) : null
    // Synthetic Proton state. "none" omits every Proton field, as older fixtures do.
    property string protonMode: "disconnected"
    property var protonStatus: null
    readonly property var shield: Proton.shield(status, protonStatus, false)
    property string protonQuery: ""
    property var switchRequest: null
    readonly property var protonCountries: [{name: "Switzerland", code: "CH"}, {name: "United States", code: "US"}, {name: "Bosnia and Herzegovina", code: "BA"}]
    readonly property var filteredCountries: protonStatus ? Proton.filterCountries(protonCountries, protonQuery) : []
    readonly property var protonCities: ({CH: [{name: "Zurich", features: ["P2P", "Tor"]}], US: [{name: "New York", features: ["P2P"]}, {name: "São Paulo test city with a long name", features: []}]})
    property string protonCountriesError: ""
    property string protonCitiesError: ""
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
    signal importSelectionFinished()

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
      protonScenario(mode === "connected" || mode === "connecting" || mode === "failed" ? "disconnected" : protonMode, true)
      query = ""
      lastAction = ""
      lastError = ""
      actionError = ""
      actionMessage = "PREVIEW ONLY — synthetic profiles; no networking commands."
    }

    // Modes: none, absent, signed-out, disconnected, connecting, connected, error, conflict, confirm.
    // Each Proton mode also sets WireGuard: connected for conflict and confirm,
    // disabled otherwise, so the shield shows the scenario it is named for.
    // scenario() passes keepWireGuard to preserve the WireGuard state it just set.
    function protonScenario(mode, keepWireGuard) {
      protonMode = mode
      switchRequest = null
      if (!keepWireGuard) {
        var wgOn = mode === "conflict" || mode === "confirm"
        status = Model.mergeStatusCatalog(Model.parseStatus(JSON.stringify({ok: true, result: wgOn
          ? {mode: "connected", enabled: true, current_profile: "preview-home", target: "profile:preview-home"}
          : {mode: "disabled", enabled: false, target: null}})), catalog)
      }
      var base = {installed: true, account: "signed-in", state: "disconnected", phase: "", error: "", message: "",
        server: "", location: "", load: "", protocol: ""}
      if (mode === "none") { protonStatus = null; return }
      if (mode === "absent") { base.installed = false; base.state = "absent" }
      if (mode === "signed-out") base.account = "signed-out"
      if (mode === "connecting") { base.state = "connecting"; base.message = "PREVIEW ONLY — Connecting Proton VPN: Switzerland" }
      if (mode === "connected" || mode === "conflict") {
        base.state = "connected"; base.server = "CH-US#1"; base.location = "New York, via Switzerland"; base.load = "34%"; base.protocol = "wireguard"
      }
      if (mode === "error") base.error = "PREVIEW ONLY — Server selection by ID is not available on the free plan."
      protonStatus = base
      if (mode === "confirm") switchRequest = {target: "proton", label: "Switzerland", choice: {kind: "country", country: "CH"}}
    }

    function connectProton(choice) { record("proton:" + JSON.stringify(Proton.connectArgs(choice))) }
    function disconnectProton() { record("proton:disconnect") }
    function protonSignIn() { record("proton:sign-in terminal refused in preview") }
    function loadProtonCountries(force) { record("proton:countries" + (force ? " refresh" : "")) }
    function loadProtonCities(code) { record("proton:cities " + code) }
    function confirmSwitch() { record("switch:" + JSON.stringify(switchRequest)); switchRequest = null }
    function cancelSwitch() { switchRequest = null }

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
    function proton(mode: string): string { fixture.protonScenario(mode); return "ok" }
    function review(): string { fixture.chooseImport(); return "ok" }
    function pickerReturned(): string {
      preview.close()
      fixture.chooseImport()
      fixture.importSelectionFinished()
      return "picker-return-v1"
    }
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
