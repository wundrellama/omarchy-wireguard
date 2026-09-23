import QtQuick
import QtQuick.Controls
import QtQuick.Layouts
import Quickshell
import Quickshell.Io
import qs.Commons
import qs.Ui
import "Model.js" as Model

Panel {
  id: root
  moduleName: "nicolasdorier.wireguard"
  ipcTarget: moduleName
  manageIpc: false

  property var serviceOverride: null
  readonly property var service: serviceOverride || liveService
  readonly property bool statusKnown: service.status.state !== "unknown" && service.status.ok !== false
  property int selectedIndex: 0
  property bool cursorActive: false
  property var themeColors: ({})
  property var reviewValues: ({})
  readonly property string reviewBatchKey: JSON.stringify([service.importPaths || [], ((service.status.importReview || {}).candidates || []).map(function(candidate) { return String(candidate.name || candidate.source_name || candidate) })])
  onReviewBatchKeyChanged: reviewValues = ({})
  readonly property url installScriptUrl: Qt.resolvedUrl("../scripts/install-backend")
  readonly property string installScriptPath: decodeURIComponent(String(installScriptUrl).replace(/^file:\/\//, ""))
  readonly property color foreground: bar ? bar.foreground : Color.foreground
  readonly property color dim: themeColors.muted || Color.muted
  readonly property color success: themeColors.green || Color.accent
  readonly property color warning: themeColors.yellow || Color.accent
  readonly property color errorColor: themeColors.red || (bar ? bar.urgent : Color.urgent)
  readonly property string fontFamily: bar ? bar.fontFamily : Style.font.family
  readonly property var locations: service.filteredLocations

  readonly property string statusCountryCode: Model.statusCountryCode(service.status)
  readonly property bool showCountryFlag: service.status.state !== "disabled" && statusCountryCode !== ""
  readonly property color stateColor: {
    if (service.status.state === "connected") return success
    if (service.status.state === "connecting") return warning
    if (service.status.state === "failed" || service.status.state === "enabled-unverified") return errorColor
    return dim
  }
  readonly property string stateLabel: {
    if (!statusKnown) return "Status unknown"
    if (!service.status.installed) return "Backend not installed"
    if (service.status.setupRequired) return "Setup required"
    return String(service.status.state || "Checking")
  }

  function clampSelection() {
    selectedIndex = Math.max(0, Math.min(locations.length - 1, selectedIndex))
  }

  function moveSelection(delta) {
    if (locations.length === 0) return
    cursorActive = true
    selectedIndex = Math.max(0, Math.min(locations.length - 1, selectedIndex + delta))
    scrollSelectedIntoView()
  }

  function activateSelected() {
    if (!statusKnown || service.busy || locations.length === 0 || selectedIndex < 0 || selectedIndex >= locations.length) return
    if (Model.shouldDisconnectLocation(locations[selectedIndex], service.status.state)) service.disconnect()
    else {
      service.connectLocation(locations[selectedIndex])
      close()
    }
  }

  function scrollSelectedIntoView() {
    Qt.callLater(function() {
      if (!locationRepeater || selectedIndex < 0 || selectedIndex >= locationRepeater.count) return
      var item = locationRepeater.itemAt(selectedIndex)
      if (!item) return
      var point = item.mapToItem(panelFlick.contentItem, 0, 0)
      if (point.y < panelFlick.contentY) panelFlick.contentY = point.y
      else if (point.y + item.height > panelFlick.contentY + panelFlick.height)
        panelFlick.contentY = point.y + item.height - panelFlick.height
    })
  }

  function setReviewValue(name, value) {
    var next = ({})
    for (var key in reviewValues) next[key] = reviewValues[key]
    next[name] = value
    reviewValues = next
  }

  function submitReview() {
    if (!statusKnown || !reviewComplete()) return
    var labels = ({})
    var candidates = service.status.importReview.candidates
    for (var i = 0; i < candidates.length; i++) {
      var name = String(candidates[i].name || candidates[i].source_name || candidates[i])
      labels[name] = reviewValues[name]
    }
    service.submitImportReview(labels)
  }

  function reviewComplete() {
    var candidates = service.status.importReview ? service.status.importReview.candidates || [] : []
    return Model.reviewComplete(candidates, reviewValues)
  }

  function open() {
    controller.show()
    service.refresh()
    Qt.callLater(function() { search.forceActiveFocus(); search.selectAll() })
  }

  implicitWidth: button.implicitWidth
  implicitHeight: button.implicitHeight

  onOpenedChanged: {
    service.panelOpen = opened
    if (opened) {
      cursorActive = false
      selectedIndex = 0
      panelFlick.contentY = 0
      Qt.callLater(function() { search.forceActiveFocus(); search.selectAll() })
    }
  }
  onLocationsChanged: clampSelection()

  FileView {
    path: Quickshell.env("HOME") + "/.local/state/omarchy/current/theme/colors.toml"
    watchChanges: true
    printErrors: false
    onLoaded: root.themeColors = Model.parseThemeColors(text())
    onFileChanged: reload()
  }

  Service {
    id: liveService
    active: root.serviceOverride === null
    settings: root.settings
    installScriptPath: root.installScriptPath
  }

  Connections {
    target: service
    function onActionFinished(action, success) {
      if (!success && root.opened) Qt.callLater(function() { search.forceActiveFocus() })
    }
  }

  IpcHandler {
    target: root.ipcTarget
    function open(): void { root.open() }
    function close(): void { root.close() }
    function show(): void { root.open() }
    function hide(): void { root.close() }
    function toggle(): void { root.toggle() }
    function refresh(): string { service.refresh(); return "ok" }
    function status(): string { return JSON.stringify(service.status) }
  }

  BarIconButton {
    id: button
    anchors.fill: parent
    bar: root.bar
    tooltipText: Model.tooltip(service.status)
    iconComponent: Component {
      Item {
        Text {
          visible: root.showCountryFlag
          anchors.centerIn: parent
          text: Model.countryFlag(root.statusCountryCode)
          font.family: root.fontFamily
          font.pixelSize: Style.bar.iconFont
        }
        Rectangle {
          visible: !root.showCountryFlag
          anchors.centerIn: parent
          width: Style.space(7)
          height: width
          radius: width / 2
          color: service.status.state === "disabled" || service.status.state === "paused" ? "transparent" : root.stateColor
          border.width: service.status.state === "disabled" || service.status.state === "paused" ? Math.max(1, Style.space(1)) : 0
          border.color: root.stateColor
        }
        Rectangle {
          visible: root.showCountryFlag
          anchors.top: parent.top
          anchors.right: parent.right
          width: Style.space(6)
          height: width
          radius: width / 2
          color: service.status.state === "paused" ? "transparent" : root.stateColor
          border.width: service.status.state === "paused" ? Math.max(1, Style.space(1)) : 0
          border.color: root.stateColor
        }
      }
    }
    onPressed: function(buttonCode) {
      if (buttonCode === Qt.LeftButton) root.toggle()
    }
  }

  KeyboardPanel {
    id: panel
    anchorItem: button
    owner: root
    bar: root.bar
    open: root.opened
    focusTarget: search
    contentWidth: panel.fittedContentWidth(Style.space(400))
    contentHeight: panel.fittedContentHeight(content.implicitHeight, Style.space(600))

    PanelKeyCatcher {
      anchors.fill: parent
      blocked: search.activeFocus
      onMoveRequested: function(dx, dy) { if (dy !== 0) root.moveSelection(dy) }
      onActivateRequested: root.activateSelected()
      onCloseRequested: root.close()
      onTabRequested: function(direction) { root.switchPanel(direction) }

      Flickable {
        id: panelFlick
        anchors.fill: parent
        contentWidth: width
        contentHeight: content.implicitHeight
        clip: true
        boundsBehavior: Flickable.StopAtBounds
        flickableDirection: Flickable.VerticalFlick
        ScrollBar.vertical: ScrollBar { policy: ScrollBar.AsNeeded }

        Column {
          id: content
          width: panelFlick.width
          spacing: Style.space(12)

          PanelHero {
            width: parent.width
            title: service.status.state === "connecting" || service.status.state === "failed" || service.status.state === "paused"
              ? (service.status.targetLabel || service.status.targetLocation || "WireGuard")
              : (service.status.location || service.status.targetLabel || service.status.targetLocation || "WireGuard")
            meta: root.stateLabel
            detail: service.status.state === "paused" ? "Paused; protection is not confirmed until connected" : "Internet exit · Full tunnel"
            foreground: root.foreground
            fontFamily: root.fontFamily
            iconComponent: Component {
              Rectangle {
                width: Style.font.display * 0.55
                height: width
                radius: width / 2
                color: service.status.state === "disabled" || service.status.state === "paused" ? "transparent" : root.stateColor
                border.width: service.status.state === "disabled" || service.status.state === "paused" ? Math.max(1, Style.space(2)) : 0
                border.color: root.stateColor
              }
            }
          }

          Text {
            visible: service.status.reason || service.actionError || service.lastError || service.actionMessage
            width: parent.width
            text: service.actionError || service.lastError || service.status.reason || service.actionMessage
            textFormat: Text.PlainText
            color: service.actionError || service.lastError || service.status.state === "failed" ? root.errorColor : root.dim
            font.family: root.fontFamily
            font.pixelSize: Style.font.bodySmall
            wrapMode: Text.WordWrap
          }

          Column {
            visible: !root.statusKnown || !service.status.installed || service.status.setupRequired
            width: parent.width
            spacing: Style.space(8)
            PanelSectionHeader { text: "GET STARTED"; foreground: root.foreground; fontFamily: root.fontFamily }
            Text {
              width: parent.width
              text: !root.statusKnown
                ? "Backend status is unknown. Install or repair only if needed; authorization is required."
                : service.status.installed
                ? "Import full-tunnel WireGuard profiles individually, as a directory, or as a ZIP. Split routes are not supported."
                : "Install the privileged WireGuard backend first, then import a compatible WireGuard profile."
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              wrapMode: Text.WordWrap
            }
            Flow {
              width: parent.width
              spacing: Style.space(6)
              Button { visible: !root.statusKnown || !service.status.installed; enabled: service.active === true && !service.busy && !!service.installScriptPath && !!service.currentUser; focusable: true; text: root.statusKnown ? "Install backend" : "Install / repair backend"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.installBackend() }
              Button { focusable: true; text: "Open TorGuard generator"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.openGenerator() }
            }
          }

          Column {
            visible: Array.isArray(service.status.errors) && service.status.errors.length > 0
            width: parent.width
            spacing: Style.space(5)
            PanelSectionHeader { text: "ERRORS"; foreground: root.errorColor; fontFamily: root.fontFamily }
            Repeater {
              model: service.status.errors || []
              Text {
                required property var modelData
                width: parent.width
                text: String(modelData)
                color: root.errorColor
                font.family: root.fontFamily
                font.pixelSize: Style.font.bodySmall
                wrapMode: Text.WordWrap
              }
            }
          }

          Column {
            visible: !!service.status.importReview && service.status.importReview.ambiguous === true
            width: parent.width
            spacing: Style.space(5)
            PanelSectionHeader { text: "IMPORT REVIEW"; foreground: root.warning; fontFamily: root.fontFamily }
            Text {
              width: parent.width
              text: service.status.importReview.message || "Give each source a display label (up to 128 printable characters)."
              color: root.warning
              font.family: root.fontFamily
              font.pixelSize: Style.font.bodySmall
              wrapMode: Text.WordWrap
            }
            Repeater {
              model: service.status.importReview.candidates || []
              ReviewRow {
                required property var modelData
                width: parent.width
                sourceName: String(modelData.name || modelData.source_name || modelData)
              }
            }
            Button { text: "Import reviewed profiles"; enabled: root.statusKnown && !service.busy && root.reviewComplete(); focusable: true; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: root.submitReview() }
          }

          Row {
            width: parent.width
            spacing: Style.space(6)
            Button { visible: service.status.installed && service.status.state === "failed"; focusable: true; text: "Retry"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.retry() }
            Button { visible: !root.statusKnown && service.disconnectRecovery === true; enabled: !service.busy; focusable: true; text: "Disconnect"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.disconnect() }
            Button { visible: !root.statusKnown; focusable: true; text: "Refresh status"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.refresh() }
            Button { visible: service.status.installed; enabled: !service.busy; focusable: true; text: "Copy diagnostics"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.copyDiagnostics() }
          }

          PanelSeparator { visible: service.status.installed; foreground: root.foreground }

          Column {
            visible: service.status.installed || root.locations.length > 0
            width: parent.width
            spacing: Style.space(8)
            PanelSectionHeader { text: "PROFILES"; foreground: root.foreground; fontFamily: root.fontFamily }
            TextField {
              id: search
              width: parent.width
              foreground: root.foreground
              placeholderText: "Search name, source, city or country"
              text: service.query
              onTextChanged: { service.query = text; root.selectedIndex = 0 }
              onAccepted: root.activateSelected()
              Keys.onPressed: function(event) {
                if (event.key === Qt.Key_Down) { root.moveSelection(1); event.accepted = true }
                else if (event.key === Qt.Key_Up) { root.moveSelection(-1); event.accepted = true }
                else if (event.key === Qt.Key_Escape) { root.close(); event.accepted = true }
              }
            }
            Text {
              visible: root.locations.length === 0
              width: parent.width
              text: "No matching profiles"
              color: root.dim
              font.family: root.fontFamily
              font.pixelSize: Style.font.body
              horizontalAlignment: Text.AlignHCenter
            }
            Column {
              id: locationColumn
              width: parent.width
              spacing: Style.space(5)
              Repeater {
                id: locationRepeater
                model: root.locations
                LocationRow {
                  required property var modelData
                  required property int index
                  width: locationColumn.width
                  location: modelData
                  rowIndex: index
                }
              }
            }
          }

          PanelSeparator { foreground: root.foreground }

          Row {
            visible: service.status.installed
            spacing: Style.space(6)
            Button { enabled: root.statusKnown && !service.busy; focusable: true; text: "Import profiles"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.chooseImport(false) }
            Button { enabled: root.statusKnown && !service.busy; focusable: true; text: "Directory"; foreground: root.foreground; fontFamily: root.fontFamily; onClicked: service.chooseImport(true) }
          }

          Column {
            visible: service.status.installed
            width: parent.width
            spacing: Style.space(6)
            PanelSeparator { width: parent.width; foreground: root.foreground }
            PanelSectionHeader { text: "BACKEND MAINTENANCE"; foreground: root.foreground; fontFamily: root.fontFamily }
            Button {
              enabled: root.statusKnown && !service.busy
              focusable: true
              text: "Uninstall backend"
              foreground: root.errorColor
              fontFamily: root.fontFamily
              onClicked: service.uninstallBackend()
            }
          }
        }
      }
    }
  }

  component LocationRow: CursorSurface {
    id: row
    property var location: null
    property int rowIndex: 0
    readonly property bool currentOrTarget: location && (location.current || location.target)
    readonly property bool disconnectAction: Model.shouldDisconnectLocation(location, service.status.state)
    enabled: root.statusKnown && !service.busy
    hasCursor: root.cursorActive && root.selectedIndex === rowIndex
    current: currentOrTarget
    foreground: root.foreground
    implicitHeight: labels.implicitHeight + Style.spacing.rowPaddingX

    MouseArea {
      anchors.fill: parent
      hoverEnabled: true
      cursorShape: Qt.PointingHandCursor
      onEntered: { root.cursorActive = true; root.selectedIndex = row.rowIndex }
      onClicked: {
        if (row.disconnectAction) service.disconnect()
        else { service.connectLocation(row.location); root.close() }
      }
    }

    RowLayout {
      anchors.left: parent.left
      anchors.right: parent.right
      anchors.verticalCenter: parent.verticalCenter
      anchors.leftMargin: Style.space(9)
      anchors.rightMargin: Style.space(9)
      spacing: Style.space(9)
      Text {
        text: Model.countryFlag(row.location ? row.location.countryCode : "")
        color: root.foreground
        font.family: root.fontFamily
        font.pixelSize: Style.font.heading
        Layout.preferredWidth: Style.space(28)
      }
      ColumnLayout {
        id: labels
        Layout.fillWidth: true
        spacing: Style.space(1)
        Text { Layout.fillWidth: true; text: row.location ? (row.location.label || row.location.city) : ""; textFormat: Text.PlainText; color: root.foreground; font.family: root.fontFamily; font.pixelSize: Style.font.body; font.bold: row.currentOrTarget; elide: Text.ElideRight }
        Text { Layout.fillWidth: true; text: "Internet exit" + (row.location && (row.location.city || row.location.country) ? " · " + [row.location.city, row.location.country].filter(function(v) { return !!v }).join(", ") : ""); textFormat: Text.PlainText; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideRight }
      }
      Text {
        text: !root.statusKnown ? "Unknown" : (row.disconnectAction ? "Disconnect" : (row.location && row.location.target && service.status.state === "connecting" ? "Connecting" : "Connect"))
        color: row.disconnectAction && service.status.state === "failed" ? root.errorColor : root.dim
        font.family: root.fontFamily
        font.pixelSize: Style.font.caption
      }
    }
  }

  component ReviewRow: Column {
    property string sourceName: ""
    width: parent ? parent.width : 0
    spacing: Style.space(4)
    Text { width: parent.width; text: sourceName; color: root.dim; font.family: root.fontFamily; font.pixelSize: Style.font.caption; elide: Text.ElideMiddle }
    TextField {
      width: parent.width
      foreground: root.foreground
      placeholderText: "Display label"
      maximumLength: 128
      text: root.reviewValues[sourceName] || ""
      onTextEdited: root.setReviewValue(sourceName, text)
    }
  }
}
