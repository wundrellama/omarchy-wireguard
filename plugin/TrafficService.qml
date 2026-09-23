import QtQuick
import Quickshell.Io
import "Traffic.js" as Traffic

Item {
  id: root
  property string profile: ""
  property var traffic: null
  property int generation: 0
  readonly property string helperPath: decodeURIComponent(String(Qt.resolvedUrl("traffic.py")).replace(/^file:\/\//, ""))

  function applySample(raw, revision, requestedProfile) {
    if (!profile || revision !== generation || requestedProfile !== profile) return
    traffic = Traffic.accept(traffic, raw, profile)
  }

  function sample() {
    if (!profile || reader.running) return
    reader.revision = generation
    reader.requestedProfile = profile
    reader.command = ["python3", "-B", helperPath, profile]
    reader.running = true
    deadline.restart()
  }

  onProfileChanged: {
    generation++
    traffic = null
    // Do not recycle an in-flight Process; its captured generation remains old.
    if (profile) Qt.callLater(sample)
  }

  Timer {
    interval: 1000
    running: root.profile !== ""
    repeat: true
    onTriggered: root.sample()
  }
  Timer {
    id: deadline
    interval: 2000
    onTriggered: {
      root.generation++
      root.traffic = null
      reader.running = false
    }
  }
  Timer {
    id: stale
    interval: 3000
    onTriggered: root.traffic = null
  }
  Process {
    id: reader
    property int revision: -1
    property string requestedProfile: ""
    stdout: StdioCollector { id: output; waitForEnd: true }
    onExited: function(exitCode) {
      deadline.stop()
      root.applySample(exitCode === 0 ? output.text : "", revision, requestedProfile)
      if (root.traffic) stale.restart()
    }
  }
}
