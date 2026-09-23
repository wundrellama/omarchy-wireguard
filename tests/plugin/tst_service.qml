import QtQuick
import QtTest
import "../../plugin" as Plugin

TestCase {
  name: "WireGuardService"
  Plugin.Service { id: service; active: false }
  function test_inactive() {
    service.refresh()
    service.connectLocation({ id: "a", kind: "profile" })
    service.disconnect()
    service.retry()
    service.chooseImport(false)
    service.installBackend()
    service.uninstallBackend()
    service.copyDiagnostics()
    service.openGenerator()
    service.notify("test", "must not appear", "normal")
    compare(service.busy, false)
    compare(service.refreshing, false)
    compare(service.pendingAction, "")
  }
  function test_statusLoss() {
    service.applyStatus('{"mode":"connected","enabled":true}')
    compare(service.status.state, "connected")
    service.applyStatus('broken')
    compare(service.status.state, "unknown")
    service.applyStatus('{"mode":"connected","enabled":true}')
    service.markCliUnavailable("failed command")
    compare(service.status.state, "unknown")
    verify(service.status.enabled !== false)
    service.applyStatus('{"mode":"connected","enabled":true}')
    service.lastStatusAt = Date.now() - 400000
    service.expireStatus()
    compare(service.status.state, "unknown")
  }
  function test_backendError() {
    service.applyActionOutput('{"ok":false,"error":{"code":"duplicate","message":"Already imported"}}')
    compare(service.actionError, "Already imported")
    service.applyActionOutput('garbage')
    compare(service.status.state, "unknown")
  }
}
