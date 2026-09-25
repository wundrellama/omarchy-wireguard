const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const read = name => fs.readFileSync(path.join(__dirname, '../../plugin/' + name), 'utf8')
const load = name => { const c = {}; vm.createContext(c); vm.runInContext(read(name), c); return c }
const Model = load('Model.js'), Proton = load('Proton.js')
// Quick-connect logic lives in Proton.js next to the validators it reuses.
const QC = { fromLocation: Proton.lastFromLocation, fromChoice: Proton.lastFromChoice, parseStored: Proton.parseLastConnection, action: Proton.quickAction }
const source = read('Service.qml')
const panel = read('BarWidget.qml')

// ---- records: kind + validated value + label, nothing else --------------------
const home = { id: 'home', kind: 'profile', label: 'Home', profileIds: ['home'] }
const work = { id: 'work', kind: 'profile', label: 'Work', profileIds: ['work'] }
const locations = [home, work]
const plain = r => JSON.parse(JSON.stringify(r))
assert.deepEqual(plain(QC.fromLocation(home)), { version: 1, kind: 'wireguard', value: 'home', label: 'Home' })
assert.deepEqual(plain(QC.fromChoice({ kind: 'server', server: 'US-CA#370' })), { version: 1, kind: 'server', value: 'US-CA#370', label: 'US-CA#370' })
assert.deepEqual(plain(QC.fromChoice({ kind: 'country', country: 'CH', name: 'Switzerland' })), { version: 1, kind: 'country', value: 'CH', label: 'Switzerland' })
assert.deepEqual(plain(QC.fromChoice({ kind: 'city', country: 'US', city: 'Los Angeles' })), { version: 1, kind: 'city', value: 'Los Angeles', label: 'Los Angeles' })
for (const kind of ['fastest', 'random', 'p2p', 'securecore', 'tor'])
  assert.deepEqual(plain(QC.fromChoice({ kind })), { version: 1, kind, value: '', label: Proton.choiceLabel({ kind }) })
for (const bad of [null, { kind: 'server', server: '--help' }, { kind: 'country', country: 'ch' }, { kind: 'city', city: '-rf' }, { kind: 'shell' }])
  assert.equal(QC.fromChoice(bad), null)
assert.equal(QC.fromLocation({ kind: 'profile', label: 'x' }), null, 'a location needs an id')

// Stored data is validated with the connect validators; anything odd is dropped.
const stored = c => JSON.stringify({ ok: true, connection: c })
assert.deepEqual(plain(QC.parseStored(stored({ version: 1, kind: 'server', value: 'US-CA#370', label: 'US-CA#370' }))).value, 'US-CA#370')
for (const bad of ['', '{', '{"ok":false}', stored(null),
  stored({ version: 1, kind: 'server', value: 'US-CA#370; rm', label: 'x' }),
  stored({ version: 1, kind: 'country', value: 'Switzerland', label: 'x' }),
  stored({ version: 1, kind: 'city', value: '-x', label: 'x' }),
  stored({ version: 1, kind: 'fastest', value: 'x', label: 'Fastest' }),
  stored({ version: 1, kind: 'wireguard', value: '', label: 'x' }),
  stored({ version: 1, kind: 'wireguard', value: 'home', label: 'a\nb' }),
  stored({ version: 2, kind: 'fastest', value: '', label: 'Fastest' }),
  stored({ version: 1, kind: 'fastest', value: '', label: 'Fastest', account: 'someone' })])
  assert.equal(QC.parseStored(bad), null, bad)

// ---- the one-button action for every state ----------------------------------
const disabled = { state: 'disabled', enabled: false, locations }
const signedIn = { installed: true, account: 'signed-in', state: 'disconnected', phase: '' }
const ctx = over => Object.assign({ wg: disabled, recovery: false, wgAbsent: false, proton: signedIn, switching: false, busy: false,
  record: null, locations, mru: [], countries: [{ name: 'Switzerland', code: 'CH' }] }, over)
const act = over => QC.action(ctx(over))
const rec = choice => choice.kind === 'wireguard' ? choice : QC.fromChoice(choice)

// Nothing active: reconnect the last choice with the existing connect path.
for (const [record, label, vpn] of [
  [{ version: 1, kind: 'wireguard', value: 'home', label: 'Old label' }, 'Connect: Home', 'wireguard'],
  [rec({ kind: 'server', server: 'US-CA#370' }), 'Connect: Proton US-CA#370', 'proton'],
  [rec({ kind: 'fastest' }), 'Connect: Proton Fastest', 'proton'],
  [rec({ kind: 'random' }), 'Connect: Proton Random', 'proton'],
  [rec({ kind: 'p2p' }), 'Connect: Proton Fastest P2P', 'proton'],
  [rec({ kind: 'securecore' }), 'Connect: Proton Secure Core', 'proton'],
  [rec({ kind: 'tor' }), 'Connect: Proton Tor', 'proton'],
  [rec({ kind: 'country', country: 'CH', name: 'Switzerland' }), 'Connect: Proton Switzerland', 'proton'],
  [rec({ kind: 'city', country: 'US', city: 'Los Angeles' }), 'Connect: Proton Los Angeles', 'proton']]) {
  const a = act({ record })
  assert.equal(a.mode, 'connect', label); assert.equal(a.label, label); assert.equal(a.vpn, vpn); assert.equal(a.enabled, true)
  if (vpn === 'wireguard') assert.equal(a.target.location, home)
  else assert.ok(Proton.connectArgs(a.target.choice), 'Proton target passes connectArgs')
}
// Country label comes from the current country list when the stored label is gone.
assert.equal(act({ record: { version: 1, kind: 'country', value: 'CH', label: 'CH' } }).label, 'Connect: Proton Switzerland')
// Busy disables, but never changes the target.
assert.equal(act({ record: rec({ kind: 'tor' }), busy: true }).enabled, false)
// A running Proton command (connect, disconnect, config read) disables it too.
assert.equal(act({ record: rec({ kind: 'tor' }), protonBusy: true }).enabled, false, 'Proton busy disables connect')
for (const state of ['connecting', 'connected'])
  assert.equal(act({ proton: Object.assign({}, signedIn, { state }), protonBusy: true }).enabled, false, 'Proton busy disables ' + state)

// Fallbacks: removed profile -> backend MRU -> Proton Fastest (signed in) -> hidden.
const gone = { version: 1, kind: 'wireguard', value: 'deleted', label: 'Deleted' }
assert.equal(act({ record: gone, mru: ['work', 'home'] }).label, 'Connect: Work')
assert.equal(act({ record: gone }).label, 'Connect: Proton Fastest')
assert.equal(act({ record: null, mru: ['nope'] }).label, 'Connect: Proton Fastest')
assert.equal(act({ record: null, proton: Object.assign({}, signedIn, { account: 'unknown' }) }).mode, 'hidden')
assert.equal(act({ record: null, proton: { installed: false, state: 'absent' } }).mode, 'hidden')
assert.equal(act({ record: null, proton: null }).mode, 'hidden')
// A Proton history entry is not offered when Proton is signed out or missing.
assert.equal(act({ record: rec({ kind: 'tor' }), proton: Object.assign({}, signedIn, { account: 'signed-out' }), mru: ['home'] }).label, 'Connect: Home')
assert.equal(act({ record: rec({ kind: 'tor' }), proton: { installed: false, state: 'absent' } }).mode, 'hidden')
// Legacy city catalogs: the MRU profile maps to its city location.
const city = { id: 'Switzerland/Zurich', kind: 'city', label: 'Zurich', profileIds: ['zh-1'] }
assert.equal(act({ record: null, locations: [city], mru: ['zh-1'], wg: { state: 'disabled', enabled: false } }).target.location, city)

// WireGuard active (connected, connecting, failed, unverified, paused): disconnect it.
for (const state of ['connected', 'connecting', 'failed', 'enabled-unverified', 'paused']) {
  const a = act({ wg: { state, enabled: true, location: state === 'connected' ? 'Home' : '', targetLabel: 'Home' }, record: rec({ kind: 'tor' }) })
  assert.equal(a.mode, 'disconnect', state); assert.equal(a.vpn, 'wireguard'); assert.equal(a.label, 'Disconnect Home')
}
assert.equal(act({ wg: { state: 'connected', enabled: true } }).label, 'Disconnect WireGuard')
// Proton active, including a connection started outside the panel (no history at all).
for (const state of ['connected', 'connecting']) {
  const a = act({ proton: Object.assign({}, signedIn, { state, server: 'CH#12' }), record: null })
  assert.equal(a.mode, 'disconnect'); assert.equal(a.vpn, 'proton'); assert.equal(a.label, 'Disconnect Proton VPN'); assert.equal(a.enabled, true)
}
assert.equal(act({ proton: Object.assign({}, signedIn, { state: 'disconnecting' }) }).enabled, false)
// Proton connected while WireGuard is known absent (backend not installed) still disconnects Proton.
assert.equal(act({ wg: { state: 'unknown' }, wgAbsent: true, proton: Object.assign({}, signedIn, { state: 'connected' }) }).vpn, 'proton')
// Both active: never guess which one to stop.
const both = act({ wg: { state: 'connected', enabled: true }, proton: Object.assign({}, signedIn, { state: 'connected' }) })
assert.equal(both.mode, 'disabled'); assert.equal(both.enabled, false); assert.match(both.label, /[Cc]onflict/)
// Unknown on either side: no connection is started, no disconnect is guessed.
for (const over of [{ wg: { state: 'unknown' } }, { wg: { state: 'unknown' }, recovery: true },
  { proton: Object.assign({}, signedIn, { state: 'unknown' }) },
  { wg: { state: 'unknown' }, proton: Object.assign({}, signedIn, { state: 'connected' }) }]) {
  const a = act(Object.assign({ record: rec({ kind: 'fastest' }) }, over))
  assert.equal(a.mode, 'disabled', JSON.stringify(over)); assert.equal(a.enabled, false); assert.match(a.label, /unknown/i)
}
// A switch in progress disables the button.
assert.equal(act({ switching: true, record: rec({ kind: 'tor' }) }).enabled, false)
assert.equal(act({ proton: Object.assign({}, signedIn, { phase: 'wg-wait' }) }).enabled, false)
// Unknown WireGuard with Proton not installed and the backend absent: nothing can connect, hidden.
assert.equal(act({ wg: { state: 'unknown' }, wgAbsent: true, proton: { installed: false, state: 'absent' } }).mode, 'hidden')

// ---- Service wiring: production bodies with inert processes -----------------
function service() {
  const log = [], queue = [], writes = []
  const s = { Model, Proton, Date, JSON, log, writes, queue, active: true, status: Model.unknownStatus(),
    catalog: { locations: [], mru: [] }, disconnectRecovery: false, wireGuardRecovery: false, wireGuardObservationAfter: 0, lastStatusAt: 0, closedRefreshIntervalSec: 30, panelOpen: true,
    lastError: '', actionError: '', pendingAction: '', actionMessage: '', refreshing: false, statusRevision: 0,
    sawFirstStatus: false, previousState: '', previousPaused: false, failureNotificationShown: false,
    handshakeFailureConfirmationPending: false, importPaths: [], currentUser: 'tester', installScriptPath: '/not/executed',
    switchRequest: null, switchTarget: null, switchPhase: '', switchStartedAt: 0, wgReleasedAfter: 0, protonReleasedAfter: 0,
    lastConnection: null, pendingConnection: null, lastConnectionHelper: '/not/executed/last_connection.py',
    Qt: { callLater(f) { queue.push(f) } }, Quickshell: { execDetached(argv) { log.push(['detached', argv[0]]) } },
    delayedRefresh: { restart() {} }, handshakeFailureNotificationDelay: { restart() {}, stop() {} }, actionFinished() {} }
  for (const name of ['statusProcess', 'listProcess', 'actionProcess', 'pickerProcess', 'installProcess', 'diagnosticsProcess', 'clipboardProcess', 'lastConnectionReader'])
    s[name] = { running: false }
  let writerRunning = false
  s.lastConnectionWriter = { get running() { return writerRunning }, set running(v) { if (v) writes.push(this.command); writerRunning = false } }
  s.protonService = { status: { state: 'disconnected', installed: true, account: 'signed-in' }, busy: false, countries: [], servers: [], cities: {},
    nm: { ok: true, at: 1, match: 'none' }, cli: { ok: true, at: 1, state: 'disconnected' },
    connect(choice) { if (this.busy) return false; log.push(['proton', ...Proton.connectArgs(choice)]); this.busy = true; return true },
    disconnect() { if (this.busy) return false; log.push(['proton', 'disconnect']); this.busy = true; return true },
    readKillSwitch() { log.push(['proton', 'config', 'list']); return true }, refresh() {}, loadServers() {}, loadCountries() {} }
  // Service.busy without the Proton term: the quick button must read protonService.busy itself.
  Object.defineProperty(s, 'busy', { get() { return s.actionProcess.running || s.pickerProcess.running || s.installProcess.running || s.switchPhase !== '' } })
  const re = /^  function (\w+)\(([^)]*)\) \{/gm; let m
  while ((m = re.exec(source))) {
    let start = re.lastIndex, depth = 1, end = start
    while (depth && end < source.length) { if (source[end] === '{') depth++; if (source[end] === '}') depth--; end++ }
    s[m[1]] = new Function(...m[2].split(',').map(x => x.trim()).filter(Boolean), 'with(this){' + source.slice(start, end - 1) + '}')
  }
  const binding = source.match(/readonly property var quickAction: ([^\n]+)/)
  assert.ok(binding, 'Service.quickAction binding missing')
  Object.defineProperty(s, 'quickAction', { get() { return new Function('with(this){return ' + binding[1] + '}').call(s) } })
  s.flush = () => { while (queue.length) queue.shift().call(s) }
  s.wgExit = (ok, stdout = '') => { s.actionProcess.running = false; s.pendingAction = ''; if (ok && stdout) s.applyActionOutput(stdout); s.wireGuardActionDone(ok); s.flush() }
  s.poll = raw => { s.applyPoll(raw, Date.now(), s.statusRevision); s.flush() }
  return s
}
const listed = Model.parseCatalog(JSON.stringify({ ok: true, result: { profiles: [{ id: 'home', label: 'Home' }, { id: 'work', label: 'Work' }], mru: ['work'] } }))
assert.deepEqual(plain(listed.mru), ['work'], 'the catalog keeps the backend MRU for the fallback')
const tick = () => { const t = Date.now(); while (Date.now() === t) {} }
const connectedHome = '{"mode":"connected","enabled":true,"current_profile":"home"}'
const disabledRaw = '{"mode":"disabled","enabled":false}'
const helperArgs = cmd => cmd.slice(0, 3).concat(cmd.slice(3, 4))

{ // Reading history runs the helper with fixed argv, then validates the result.
  const s = service()
  s.loadLastConnection()
  assert.deepEqual(s.lastConnectionReader.command, ['python3', '-B', '/not/executed/last_connection.py', 'read'])
  s.applyLastConnection(stored({ version: 1, kind: 'tor', value: '', label: 'Tor' }))
  assert.equal(s.lastConnection.kind, 'tor')
  s.applyLastConnection('{broken'); assert.equal(s.lastConnection, null, 'invalid history falls back')
}
{ // WireGuard: recorded only when the backend reports the chosen profile connected.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.connectLocation(s.status.locations.find(x => x.id === 'home'))
  assert.deepEqual(s.actionProcess.command, ['omarchy-wireguard', 'connect', '--profile', 'home'])
  assert.equal(s.writes.length, 0, 'not recorded when the connect is only started')
  s.wgExit(true, '{"mode":"connecting","enabled":true}')
  assert.equal(s.writes.length, 0)
  tick(); s.poll(connectedHome)
  assert.equal(s.writes.length, 1)
  assert.deepEqual(helperArgs(s.writes[0]), ['python3', '-B', '/not/executed/last_connection.py', 'write'])
  assert.deepEqual(JSON.parse(s.writes[0][4]), { version: 1, kind: 'wireguard', value: 'home', label: 'Home' })
  assert.equal(s.writes[0].length, 5, 'argv only, one JSON argument')
  assert.equal(s.lastConnection.value, 'home'); assert.equal(s.pendingConnection, null)
  tick(); s.poll(connectedHome); assert.equal(s.writes.length, 1, 'recorded once')
}
{ // A failed WireGuard connect is not recorded.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.connectLocation(s.status.locations.find(x => x.id === 'work'))
  s.wgExit(true, '{"mode":"failed","enabled":true,"last_error":"x"}')
  tick(); s.poll('{"mode":"connected","enabled":true,"current_profile":"home"}')
  assert.equal(s.writes.length, 0, 'a different profile connecting is not this choice')
}
{ // A WireGuard connect command that fails clears the pending choice.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.connectLocation(s.status.locations.find(x => x.id === 'home'))
  assert.equal(s.pendingConnection.value, 'home')
  s.wgExit(false)
  assert.equal(s.pendingConnection, null, 'failed action clears the pending choice')
  tick(); s.poll(connectedHome)
  assert.equal(s.writes.length, 0, 'a later connection made elsewhere is not recorded')
}
for (const after of [disabledRaw, '{"mode":"failed","enabled":true,"last_error":"x"}']) {
  // The action ran, but a later poll shows the attempt ended without connecting.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.connectLocation(s.status.locations.find(x => x.id === 'home'))
  s.wgExit(true, '{"mode":"connecting","enabled":true}')
  assert.equal(s.pendingConnection.value, 'home', 'connecting keeps the pending choice')
  tick(); s.poll(after)
  assert.equal(s.pendingConnection, null, after)
  tick(); s.poll(connectedHome)
  assert.equal(s.writes.length, 0, after + ' then connected elsewhere is not recorded')
}
{ // A write that is still running keeps the latest record and writes it next.
  const s = service()
  let running = false
  s.lastConnectionWriter = { get running() { return running }, set running(v) { if (v) { assert.equal(running, false, 'one writer at a time'); s.writes.push(this.command) } running = v } }
  const a = QC.fromChoice({ kind: 'tor' }), b = QC.fromChoice({ kind: 'p2p' }), c = QC.fromChoice({ kind: 'fastest' })
  s.recordConnection(a); s.recordConnection(b); s.recordConnection(c)
  assert.equal(s.writes.length, 1)
  assert.equal(s.lastConnection.kind, 'fastest', 'the panel shows the latest choice at once')
  running = false; s.lastConnectionWritten()
  assert.equal(s.writes.length, 2)
  assert.equal(JSON.parse(s.writes[1][4]).kind, 'fastest', 'only the latest queued record is written')
  running = false; s.lastConnectionWritten()
  assert.equal(s.writes.length, 2, 'nothing more to write')
}
{ // The history reader is bounded like the other commands.
  const s = service()
  s.loadLastConnection(); assert.equal(s.lastConnectionReader.running, true)
  s.expireLastConnection(); assert.equal(s.lastConnectionReader.running, true, 'a fresh read keeps running')
  s.lastConnectionReader.startedAt = Date.now() - 60000
  s.expireLastConnection(); assert.equal(s.lastConnectionReader.running, false, 'a hung read is stopped')
}
{ // A panel-started Proton command disables the quick button.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.lastConnection = QC.fromChoice({ kind: 'tor' })
  assert.equal(s.quickAction.enabled, true)
  s.connectProton({ kind: 'server', server: 'US-CA#370' })
  s.protonService.status = { state: 'connecting', installed: true, account: 'signed-in' }
  assert.equal(s.quickAction.enabled, false, 'Proton connect in progress')
  const k = service(); k.catalog = listed; k.applyStatus(disabledRaw)
  k.lastConnection = QC.fromChoice({ kind: 'tor' }); k.protonService.busy = true
  assert.equal(k.quickAction.mode, 'connect'); assert.equal(k.quickAction.enabled, false, 'Proton config read in progress')
}
{ // Proton: recorded when `protonvpn connect` succeeds, not on failure.
  const s = service(); s.applyStatus(disabledRaw)
  s.connectProton({ kind: 'server', server: 'US-CA#370' })
  assert.equal(s.writes.length, 0)
  s.protonService.busy = false; s.protonActionDone('connect', true, ''); s.flush()
  assert.equal(JSON.parse(s.writes[0][4]).value, 'US-CA#370')
  const f = service(); f.applyStatus(disabledRaw); f.connectProton({ kind: 'city', country: 'US', city: 'Los Angeles' })
  f.protonService.busy = false; f.protonActionDone('connect', false, 'nope'); f.flush()
  assert.equal(f.writes.length, 0); assert.equal(f.pendingConnection, null)
}
{ // Through the confirmed switch, WireGuard -> Proton records the Proton choice after it connects.
  const s = service(); s.catalog = listed; s.applyStatus(connectedHome)
  s.connectProton({ kind: 'country', country: 'CH', name: 'Switzerland' }); s.confirmSwitch()
  tick(); s.wgExit(true, disabledRaw); tick(); s.poll(disabledRaw)
  assert.deepEqual(s.log, [['proton', 'connect', '--country', 'CH']])
  s.protonService.busy = false; s.protonActionDone('connect', true, ''); s.flush()
  assert.deepEqual(JSON.parse(s.writes[0][4]), { version: 1, kind: 'country', value: 'CH', label: 'Switzerland' })
}
{ // An aborted switch records nothing.
  const s = service(); s.applyStatus(connectedHome)
  s.connectProton({ kind: 'tor' }); s.confirmSwitch(); s.wgExit(false)
  s.protonService.busy = false; s.protonActionDone('connect', true, ''); s.flush()
  assert.equal(s.writes.length, 0)
}
{ // quickConnect uses the existing paths, including switch confirmation.
  const s = service(); s.catalog = listed; s.applyStatus(disabledRaw)
  s.lastConnection = QC.fromChoice({ kind: 'tor' })
  assert.equal(s.quickAction.label, 'Connect: Proton Tor')
  s.quickConnect(); assert.deepEqual(s.log, [['proton', 'connect', '--tor']])
  const w = service(); w.catalog = listed; w.applyStatus(disabledRaw); w.protonService.status = { state: 'connected', installed: true, account: 'signed-in' }
  assert.equal(w.quickAction.label, 'Disconnect Proton VPN')
  w.quickConnect(); assert.deepEqual(w.log, [['proton', 'disconnect']])
  const x = service(); x.catalog = listed; x.applyStatus(connectedHome)
  assert.equal(x.quickAction.label, 'Disconnect Home')
  x.quickConnect(); assert.deepEqual(x.actionProcess.command, ['omarchy-wireguard', 'disconnect'])
  const y = service(); y.catalog = listed; y.applyStatus(disabledRaw); y.protonService.status = { state: 'connected', installed: true, account: 'signed-in' }
  y.lastConnection = QC.fromLocation(listed.locations[0])
  y.protonService.status = { state: 'disconnected', installed: true, account: 'signed-in' }
  y.applyStatus(connectedHome); y.protonService.status = { state: 'connected', installed: true, account: 'signed-in' }
  assert.equal(y.quickAction.mode, 'disabled', 'conflict'); y.quickConnect()
  assert.deepEqual(y.log, []); assert.equal(y.actionProcess.running, false)
  const u = service(); u.lastConnection = QC.fromChoice({ kind: 'fastest' })
  u.quickConnect(); assert.deepEqual(u.log, [], 'unknown status never starts a connection'); assert.equal(u.actionProcess.running, false)
  const p = service(); p.catalog = listed; p.applyStatus(disabledRaw); p.protonService.status = { state: 'connected', installed: true, account: 'signed-in' }
  p.lastConnection = QC.fromLocation(listed.locations[0])
  p.protonService.status = { state: 'disconnected', installed: true, account: 'signed-in' }
  p.quickConnect(); assert.deepEqual(p.actionProcess.command, ['omarchy-wireguard', 'connect', '--profile', 'home'])
  const c = service(); c.catalog = listed; c.applyStatus(disabledRaw); c.protonService.status = { state: 'connected', installed: true, account: 'signed-in' }
  c.lastConnection = QC.fromLocation(listed.locations[0])
  // With Proton active the button disconnects Proton; it does not start a switch.
  c.quickConnect(); assert.equal(c.switchRequest, null); assert.deepEqual(c.log, [['proton', 'disconnect']])
}

// ---- unified Proton search ---------------------------------------------------
const index = Proton.parseServerIndex(JSON.stringify({ ok: true, maxTier: 2, fields: ['name', 'country', 'city', 'features', 'load', 'tier'], servers: [
  ['US-CA#370', 'US', 'Los Angeles', ['p2p'], 41, 2], ['US-CA#3', 'US', 'Los Angeles', [], 20, 2], ['US-CA#31', 'US', 'Los Angeles', [], 90, 2],
  ['CH#12', 'CH', 'Zurich', ['p2p'], 30, 2], ['FR#13-TOR', 'FR', 'Paris', ['tor'], 50, 2], ['CH-US#1', 'US', 'New York', ['securecore'], 10, 2],
  ['--help', 'US', 'Los Angeles', [], 1, 2], ['de#1', 'DE', 'Berlin', [], 1, 2], ['DE#2', 'de', 'Berlin', [], 1, 2], ['DE#3', 'DE', '-rf', [], 1, 2],
  ['DE#4', 'DE', 'Berlin', 'p2p', 1, 2], 'junk', ['JP#1', 'JP', 'Tokyo', [], 5, 2]] }))
assert.equal(index.ok, true)
assert.deepEqual(plain(index.servers.map(x => x.name).sort()), ['CH#12', 'CH-US#1', 'DE#3', 'FR#13-TOR', 'JP#1', 'US-CA#3', 'US-CA#31', 'US-CA#370'])
assert.equal(index.servers.find(x => x.name === 'DE#3').city, '')
for (const bad of ['', '{', '{"ok":false}', '{"ok":true,"servers":{}}', '[]']) assert.equal(Proton.parseServerIndex(bad).ok, false)
const countries = [{ name: 'Switzerland', code: 'CH' }, { name: 'United States', code: 'US' }, { name: 'France', code: 'FR' }, { name: 'Japan', code: 'JP' }]
const cities = { US: [{ name: 'New York', features: [] }, { name: 'Los Angeles', features: [] }], JP: [{ name: 'Osaka', features: [] }] }
const search = (q, limit) => Proton.searchProton(q, countries, cities, index.servers, limit)
const kinds = r => plain(r).map(x => x.kind + ':' + (x.code || x.city || x.server))
// Empty query browses countries only, as before.
assert.deepEqual(kinds(search('')), ['country:CH', 'country:US', 'country:FR', 'country:JP'])
// Countries by name or code, case-insensitive.
assert.deepEqual(kinds(search('swit')), ['country:CH'])
assert.ok(kinds(search('us')).includes('country:US')); assert.ok(kinds(search('US')).includes('country:US'))
// Cities from both the index and loaded city lists; servers there follow.
assert.deepEqual(kinds(search('los angeles')).slice(0, 1), ['city:Los Angeles'])
assert.deepEqual(kinds(search('LOS ANG')).filter(x => x.startsWith('server')), ['server:US-CA#3', 'server:US-CA#370', 'server:US-CA#31'])
assert.deepEqual(kinds(search('osaka')), ['city:Osaka'], 'a city from `cities list` without indexed servers')
assert.equal(search('los angeles')[0].choice.kind, 'city'); assert.equal(search('los angeles')[0].choice.city, 'Los Angeles')
assert.equal(search('los angeles')[0].country, 'US')
// Servers by name prefix, case-insensitive; exact prefix before load order.
assert.deepEqual(kinds(search('us-ca#3')), ['server:US-CA#3', 'server:US-CA#370', 'server:US-CA#31'])
assert.deepEqual(plain(search('US-CA#370')[0].choice), { kind: 'server', server: 'US-CA#370' })
// Feature words match servers.
assert.deepEqual(kinds(search('tor')), ['server:FR#13-TOR'])
assert.deepEqual(kinds(search('p2p')), ['server:CH#12', 'server:US-CA#370'])
// Every result is connectable through Proton.connectArgs; invalid names never appear.
for (const q of ['', 'us', 'los', 'ch', 'de', 'help', 'tor', 'berlin'])
  for (const r of search(q)) assert.ok(Proton.connectArgs(r.choice), q + ' ' + JSON.stringify(r))
assert.deepEqual(kinds(search('help')), []); assert.deepEqual(kinds(search('-rf')), [])
// Queries are capped (default 30); the empty browse list is not.
const many = Array.from({ length: 80 }, (_, i) => ({ name: 'US-NY#' + (i + 1), country: 'US', city: 'New York', features: [], load: i, tier: 2 }))
assert.equal(Proton.searchProton('us-ny', countries, {}, many).length, 30)
assert.equal(Proton.searchProton('us', countries, {}, many, 5).length, 5)
assert.equal(Proton.searchProton('', Array.from({ length: 120 }, (_, i) => ({ name: 'C' + i, code: 'AA' })), {}, many).length, 120)
assert.equal(Proton.searchProton("x", null, null, null).length, 0)

// ---- panel layout -------------------------------------------------------------
const at = text => { const i = panel.indexOf(text); assert.ok(i >= 0, text + ' missing'); return i }
assert.ok(at('text: "Copy diagnostics"') > at('text: "PROFILES"'), 'Copy diagnostics after profiles')
assert.ok(at('text: "Copy diagnostics"') > at('text: "PROTON VPN"'), 'Copy diagnostics after Proton')
assert.ok(at('text: "Copy diagnostics"') > at('text: "BACKEND MAINTENANCE"'), 'Copy diagnostics in maintenance')
assert.ok(at('onClicked: service.quickConnect()') < at('text: "PROFILES"'), 'quick button near the top')
const quickVisible = panel.match(/visible: ([^;\n]*quickAction[^;\n]*); enabled: ([^;\n]+);[^\n]*text: ([^;\n]+);[^\n]*onClicked: service.quickConnect\(\)/)
assert.ok(quickVisible, 'quick button bindings')
const evalBinding = (expr, service) => new Function('service', 'root', 'return ' + expr)(service, {})
assert.equal(!!evalBinding(quickVisible[1], {}), false, 'fixtures without quickAction hide it')
assert.equal(!!evalBinding(quickVisible[1], { quickAction: { mode: 'hidden' } }), false)
assert.equal(!!evalBinding(quickVisible[1], { quickAction: { mode: 'disabled', enabled: false, label: 'VPN status unknown' } }), true)
assert.equal(!!evalBinding(quickVisible[2], { quickAction: { mode: 'disabled', enabled: false } }), false)
assert.equal(evalBinding(quickVisible[3], { quickAction: { mode: 'connect', label: 'Connect: Home' } }), 'Connect: Home')
// One Proton search field; the server text field and the country-only field are gone.
assert.doesNotMatch(panel, /protonServerField|Search Proton countries"/)
assert.equal((panel.match(/service\.protonQuery/g) || []).length >= 1, true)
assert.match(panel, /service\.protonResults/)
assert.equal((panel.match(/TextField \{/g) || []).length, 3, 'profiles search, Proton search, review label')
console.log('quick connect, last connection, unified Proton search and layout tests passed')
