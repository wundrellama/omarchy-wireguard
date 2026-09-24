const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const source = fs.readFileSync(path.join(__dirname,'../../plugin/Service.qml'),'utf8')
const load = name => { const c = {}; vm.createContext(c); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/'+name),'utf8'), c); return c }
const Model = load('Model.js'), Proton = load('Proton.js')

// Production Service function bodies run against inert fake processes. Nothing is launched:
// the fake WireGuard action process and fake Proton service only record requests.
function service() {
  const log = [], queue = []
  const s = { Model, Proton, Date, log, queue, active:true, status:Model.unknownStatus(), catalog:{locations:[]},
    disconnectRecovery:false, lastStatusAt:0, closedRefreshIntervalSec:30, panelOpen:true,
    lastError:'', actionError:'', pendingAction:'', actionMessage:'', refreshing:false, statusRevision:0,
    sawFirstStatus:false, previousState:'', previousPaused:false, failureNotificationShown:false,
    handshakeFailureConfirmationPending:false, importPaths:[], currentUser:'tester', installScriptPath:'/not/executed',
    switchRequest:null, switchTarget:null, switchPhase:'', switchStartedAt:0, wgReleasedAfter:0, protonReleasedAfter:0,
    Qt:{callLater(f){queue.push(f)}},
    Quickshell:{execDetached(){throw Error('inactive detached process')}},
    delayedRefresh:{restart(){}}, handshakeFailureNotificationDelay:{restart(){},stop(){}}, actionFinished(){} }
  for (const name of ['statusProcess','listProcess','actionProcess','pickerProcess','installProcess','diagnosticsProcess','clipboardProcess']) s[name]={running:false}
  s.protonService = { status:{state:'disconnected',installed:true}, busy:false, nm:{ok:true,at:1,match:'none'}, cli:{ok:true,at:1,state:'disconnected'},
    connect(choice){ if (this.busy) return false; log.push(['proton', ...Proton.connectArgs(choice)]); this.busy=true; return true },
    disconnect(){ if (this.busy) return false; log.push(['proton','disconnect']); this.busy=true; return true },
    readKillSwitch(){ log.push(['proton','config','list']); return true }, refresh(){} }
  Object.defineProperty(s,'busy',{get(){ return s.actionProcess.running || s.pickerProcess.running || s.installProcess.running || s.protonService.busy || s.switchPhase !== '' }})
  const re = /^  function (\w+)\(([^)]*)\) \{/gm; let m
  while ((m=re.exec(source))) {
    let start=re.lastIndex, depth=1, end=start
    while(depth && end<source.length) { if(source[end]==='{') depth++; if(source[end]==='}') depth--; end++ }
    s[m[1]]=new Function(...m[2].split(',').map(x=>x.trim()).filter(Boolean), 'with(this){'+source.slice(start,end-1)+'}')
  }
  // Models the exited-before-runningChanged order: deferred work runs after the process stops.
  s.flush = () => { while (queue.length) queue.shift().call(s) }
  s.wgExit = (ok, stdout='', stderr='') => { s.actionProcess.running = false; s.actionError = ok ? '' : stderr; s.pendingAction = ''; if (ok && stdout) s.applyActionOutput(stdout); s.wireGuardActionDone(ok); s.flush() }
  s.poll = raw => { s.statusRevision; s.applyPoll(raw, Date.now(), s.statusRevision); s.flush() }
  return s
}
const enabled = '{"mode":"connected","enabled":true,"current_profile":"home"}'
const disabled = '{"mode":"disabled","enabled":false}'
const wgOnly = log => log.filter(x => x[0] === 'omarchy-wireguard')
const tick = () => { const t = Date.now(); while (Date.now() === t) {} }

// ---- WireGuard -> Proton ----------------------------------------------------
{
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'country', country:'CH'})
  assert.equal(s.switchRequest.target, 'proton', 'WireGuard active requires inline confirmation')
  assert.equal(s.actionProcess.running, false); assert.deepEqual(s.log, [])
  s.cancelSwitch(); assert.equal(s.switchRequest, null)
  s.connectProton({kind:'country', country:'CH'}); s.confirmSwitch()
  assert.deepEqual(s.actionProcess.command, ['omarchy-wireguard','disconnect'])
  assert.equal(s.switchPhase, 'wg-disconnect')
  assert.equal(s.busy, true)
  // A second request, or a WireGuard connect, is refused while switching.
  s.connectProton({kind:'fastest'}); s.connectLocation({id:'home',kind:'profile'})
  assert.deepEqual(s.log, []); assert.deepEqual(s.actionProcess.command, ['omarchy-wireguard','disconnect'])
  tick(); s.wgExit(true, disabled)
  // The disconnect's own response is not enough: a later status poll must show disabled.
  assert.equal(s.switchPhase, 'wg-wait'); assert.deepEqual(s.log, [])
  tick(); s.poll(enabled)
  assert.equal(s.switchPhase, 'wg-wait'); assert.deepEqual(s.log, [], 'never start Proton while WireGuard is enabled')
  s.poll('broken'); assert.deepEqual(s.log, [])
  tick(); s.poll(disabled)
  assert.deepEqual(s.log, [['proton','connect','--country','CH']])
  assert.equal(s.switchPhase, 'proton-connect')
  s.protonService.busy = false; s.protonActionDone('connect', true, ''); s.flush()
  assert.equal(s.switchPhase, ''); assert.equal(s.actionError, '')
}
{ // WireGuard disconnect failure aborts; Proton is never started.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'tor'}); s.confirmSwitch()
  s.wgExit(false, '', 'Backend refused')
  assert.equal(s.switchPhase, ''); assert.deepEqual(s.log, [])
  assert.match(s.actionError, /WireGuard disconnect failed.*Backend refused/)
  s.poll(disabled); assert.deepEqual(s.log, [])
}
{ // WireGuard never reports disabled: bounded wait, then abort.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'random'}); s.confirmSwitch(); s.wgExit(true)
  s.wgReleasedAfter = Date.now() - 60000; s.checkSwitchDeadline()
  assert.equal(s.switchPhase, ''); assert.match(s.actionError, /did not report disabled/)
  s.poll(disabled); assert.deepEqual(s.log, [])
}
{ // Proton connect failure after the switch is reported, WireGuard stays off.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'server', server:'IT#23'}); s.confirmSwitch(); tick(); s.wgExit(true); tick(); s.poll(disabled)
  s.protonService.busy = false; s.protonActionDone('connect', false, 'Server selection by ID is not available on the free plan.'); s.flush()
  assert.equal(s.switchPhase, ''); assert.match(s.actionError, /free plan/)
}
{ // No WireGuard: Proton connects directly with exact argv, every quick option.
  for (const [choice, argv] of [[{kind:'fastest'},['connect']],[{kind:'random'},['connect','--random']],[{kind:'p2p'},['connect','--p2p']],
      [{kind:'securecore'},['connect','--securecore']],[{kind:'tor'},['connect','--tor']],[{kind:'city',city:'New York'},['connect','--city','New York']]]) {
    const s = service(); s.applyStatus(disabled)
    s.connectProton(choice)
    assert.equal(s.switchRequest, null); assert.deepEqual(s.log, [['proton', ...argv]])
  }
  const s = service(); s.applyStatus(disabled)
  s.connectProton({kind:'country', country:'ch'}); s.connectProton({kind:'server', server:'--help'})
  assert.deepEqual(s.log, []); assert.match(s.actionError, /Invalid Proton/)
  // Unknown WireGuard status never lets Proton start blindly.
  const u = service(); u.connectProton({kind:'fastest'}); assert.deepEqual(u.log, []); assert.match(u.actionError, /unknown/)
  const r = service(); r.disconnectRecovery = true; r.connectProton({kind:'fastest'}); assert.equal(r.switchRequest.target, 'proton')
  for (const state of ['unknown','connecting','disconnecting']) {
    const q = service(); q.applyStatus(disabled); q.protonService.status = {state, installed:true}
    q.connectProton({kind:'fastest'}); assert.deepEqual(q.log, []); assert.match(q.actionError, /Proton VPN is/)
  }
  const n = service(); n.markCliUnavailable('WireGuard backend is not installed or running'); n.connectProton({kind:'fastest'})
  assert.deepEqual(n.log, [['proton','connect']])
}

// ---- Proton -> WireGuard ----------------------------------------------------
{
  const s = service(); s.applyStatus(disabled); s.protonService.status = {state:'connected', installed:true}
  const home = {id:'home', kind:'profile', label:'Home'}
  s.connectLocation(home)
  assert.equal(s.switchRequest.target, 'wireguard'); assert.equal(s.actionProcess.running, false)
  s.confirmSwitch()
  assert.equal(s.switchPhase, 'ks-check'); assert.deepEqual(s.log, [['proton','config','list']])
  for (const value of ['standard', 'advanced', '']) {
    const k = service(); k.applyStatus(disabled); k.protonService.status = {state:'connected', installed:true}
    k.connectLocation(home); k.confirmSwitch(); k.protonKillSwitchRead(value); k.flush()
    assert.equal(k.switchPhase, ''); assert.deepEqual(k.log, [['proton','config','list']], 'kill switch ' + value + ' refuses')
    assert.match(k.actionError, value ? /kill switch/ : /Could not read/)
  }
  s.protonKillSwitchRead('off'); s.flush()
  assert.equal(s.switchPhase, 'proton-disconnect'); assert.deepEqual(s.log.at(-1), ['proton','disconnect'])
  s.connectProton({kind:'fastest'}); assert.equal(s.log.length, 2, 'serialized while switching')
  tick(); s.protonService.busy = false; s.protonActionDone('disconnect', true, ''); s.flush()
  assert.equal(s.switchPhase, 'proton-wait'); assert.equal(s.actionProcess.running, false)
  // Observations from before the disconnect finished are not accepted.
  s.protonService.nm = {ok:true, at:s.protonReleasedAfter - 5, match:'none'}; s.protonService.cli = {ok:true, at:s.protonReleasedAfter - 5, state:'disconnected'}
  s.protonObserved(); s.flush(); assert.equal(s.actionProcess.running, false)
  tick(); s.protonService.nm = {ok:true, at:Date.now(), match:'none'}; s.protonService.cli = {ok:true, at:Date.now(), state:'connected'}
  s.protonObserved(); s.flush(); assert.equal(s.actionProcess.running, false, 'Proton must report Disconnected')
  s.protonService.cli = {ok:true, at:Date.now(), state:'disconnected'}
  s.protonObserved(); s.flush()
  assert.deepEqual(s.actionProcess.command, ['omarchy-wireguard','connect','--profile','home'])
  assert.equal(s.switchPhase, '')
}
{ // Proton disconnect failure aborts the switch; WireGuard is not started.
  const s = service(); s.applyStatus(disabled); s.protonService.status = {state:'connected', installed:true}
  s.connectLocation({id:'home', kind:'profile'}); s.confirmSwitch(); s.protonKillSwitchRead('off'); s.flush()
  s.protonService.busy = false; s.protonActionDone('disconnect', false, 'Proton service unavailable'); s.flush()
  assert.equal(s.switchPhase, ''); assert.equal(s.actionProcess.running, false); assert.match(s.actionError, /Proton service unavailable/)
}
{ // Unknown Proton status refuses a WireGuard connect instead of guessing.
  const s = service(); s.applyStatus(disabled); s.protonService.status = {state:'unknown', installed:true}
  s.connectLocation({id:'home', kind:'profile'})
  assert.equal(s.actionProcess.running, false); assert.equal(s.switchRequest, null); assert.match(s.actionError, /Proton VPN status is unknown/)
  const a = service(); a.applyStatus(disabled); a.protonService.status = {state:'absent', installed:false}
  a.connectLocation({id:'home', kind:'profile'}); assert.deepEqual(a.actionProcess.command, ['omarchy-wireguard','connect','--profile','home'])
}
{ // Inactive services never act; a stale confirmation cannot run twice.
  const s = service(); s.applyStatus(enabled); s.connectProton({kind:'fastest'}); s.active = false
  s.confirmSwitch(); assert.equal(s.actionProcess.running, false)
  const t = service(); t.applyStatus(enabled); t.connectProton({kind:'fastest'}); t.confirmSwitch(); t.confirmSwitch()
  assert.deepEqual(t.actionProcess.command, ['omarchy-wireguard','disconnect'])
}
// ---- whole-transition deadline ----------------------------------------------
{ // Stuck in wg-disconnect: the switch aborts at 150 s and a late success starts nothing.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'fastest'}); s.confirmSwitch()
  assert.equal(s.switchPhase, 'wg-disconnect')
  s.switchStartedAt = Date.now() - 149000; s.checkSwitchDeadline()
  assert.equal(s.switchPhase, 'wg-disconnect', 'not before the deadline')
  s.switchStartedAt = Date.now() - 151000; s.checkSwitchDeadline()
  assert.equal(s.switchPhase, ''); assert.equal(s.switchTarget, null); assert.equal(s.switchRequest, null)
  assert.match(s.actionError, /timed out/)
  tick(); s.wgExit(true, disabled); tick(); s.poll(disabled)
  assert.deepEqual(s.log, [], 'Proton never starts after the aborted switch')
  assert.equal(s.switchPhase, '')
}
{ // Stuck in proton-connect: aborts; a late Proton result neither clears the error nor starts WireGuard.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'fastest'}); s.confirmSwitch(); tick(); s.wgExit(true); tick(); s.poll(disabled)
  assert.equal(s.switchPhase, 'proton-connect')
  s.switchStartedAt = Date.now() - 151000; s.checkSwitchDeadline()
  assert.equal(s.switchPhase, ''); assert.equal(s.switchTarget, null); assert.match(s.actionError, /timed out/)
  const error = s.actionError
  s.protonService.busy = false; s.protonActionDone('connect', true, ''); s.flush()
  assert.equal(s.actionError, error); assert.equal(s.actionProcess.command[1], 'disconnect')
  assert.deepEqual(s.log, [['proton','connect']])
}
{ // Stuck in ks-check or proton-disconnect/proton-wait: late results never start WireGuard.
  const s = service(); s.applyStatus(disabled); s.protonService.status = {state:'connected', installed:true}
  s.connectLocation({id:'home', kind:'profile'}); s.confirmSwitch()
  s.switchStartedAt = Date.now() - 151000; s.checkSwitchDeadline()
  assert.equal(s.switchPhase, ''); s.protonKillSwitchRead('off'); s.flush()
  assert.deepEqual(s.log, [['proton','config','list']])
  const w = service(); w.applyStatus(disabled); w.protonService.status = {state:'connected', installed:true}
  w.connectLocation({id:'home', kind:'profile'}); w.confirmSwitch(); w.protonKillSwitchRead('off'); w.flush()
  tick(); w.protonService.busy = false; w.protonActionDone('disconnect', true, ''); w.flush()
  assert.equal(w.switchPhase, 'proton-wait')
  w.switchStartedAt = Date.now() - 151000; w.checkSwitchDeadline()
  assert.equal(w.switchPhase, '')
  tick(); w.protonService.nm = {ok:true, at:Date.now(), match:'none'}; w.protonService.cli = {ok:true, at:Date.now(), state:'disconnected'}
  w.protonObserved(); w.flush(); w.advanceSwitch()
  assert.equal(w.actionProcess.running, false, 'WireGuard never starts after the aborted switch')
}

// ---- WireGuard action timeout -------------------------------------------------
{ // A hung `omarchy-wireguard disconnect` is abandoned; the switch aborts and the panel is not wedged.
  const s = service(); s.applyStatus(enabled)
  s.connectProton({kind:'fastest'}); s.confirmSwitch()
  assert.equal(typeof s.expireAction, 'function', 'WireGuard action timeout missing')
  s.expireAction(); assert.equal(s.actionProcess.running, true, 'not before the bound')
  s.actionProcess.startedAt = Date.now() - 121000; s.expireAction(); s.flush()
  assert.equal(s.actionProcess.running, false); assert.equal(s.actionProcess.abandoned, true)
  assert.equal(s.status.state, 'unknown'); assert.match(s.actionError, /timed out/)
  assert.equal(s.switchPhase, ''); assert.equal(s.busy, false)
  tick(); s.poll(disabled); assert.deepEqual(s.log, [], 'Proton never starts after a timed-out disconnect')
  const plain = service(); plain.applyStatus(disabled); plain.connectLocation({id:'home', kind:'profile'})
  plain.actionProcess.startedAt = Date.now() - 121000; plain.expireAction()
  assert.equal(plain.actionProcess.running, false); assert.equal(plain.pendingAction, ''); assert.match(plain.actionError, /timed out/)
}
console.log('VPN switching sequences, serialization and stale-observation guards passed')
