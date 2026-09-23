# Plugin checks

Run from the repository root (no installs, privileged operations, or network changes):

```sh
node tests/plugin/model.test.js
node tests/plugin/service.test.js
node tests/plugin/panel.test.js
QT_QPA_PLATFORM=offscreen /usr/lib/qt6/bin/qmltestrunner -input tests/plugin/tst_model.qml
omarchy plugin validate .
```

The Node service tests execute production function bodies with inert process objects; they do not launch commands. Panel tests cover the injection contract and execute the actual keyboard-selection function. Model tests cover flat named catalog preference, legacy cities, searching, exact command arguments, labels, unknown/contradictory status, and paused wording. Changes were developed in incremental failing-test/passing-test cycles.

`tests/plugin/tst_service.qml` is an optional real QML Service test. On this machine stock qmltestrunner cannot load Quickshell's `quickshell-coreplugin`, so this test is **blocked**, not passed. Pure Model QML tests do run under Qt 6.11.2. Standalone qmllint exits 0 but warns that `qs.Commons` / `qs.Ui` are unresolved; that exit does not prove runtime panel correctness. The parent agent owns actual SAFE preview rendering within the existing Omarchy shell; no additional component shell instance is launched by these tests.

Preview seam: set `BarWidget.serviceOverride` during construction. The embedded `liveService.active` becomes false, blocking refresh/actions/notifications and polling timers. Production contains no fixture status. The override retains existing service method names; `chooseImport(directory)` now takes one boolean, `submitImportReview(labels)` accepts `{sourceName: displayLabel}`. Optional `disconnectRecovery: true` shows explicit recovery Disconnect after a previously observed enabled connection; omitted/false hides it. `targetLabel` is an optional named hero label. Parent fixtures should implement `refresh()` as well.

Status loss is unknown, not disconnected. Polls older than ten seconds and polls from before an action are ignored; a periodic freshness check invalidates expired status. Unsafe mutation UI is disabled/hidden while unknown; explicit recovery Disconnect is allowed only after previously observed enabled/connected state. Timed pause control is removed, and inherited paused status never promises restored protection. No network/protection verification is claimed by these UI tests.
