const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const source = fs.readFileSync(path.join(__dirname,'../../plugin/ProtonService.qml'),'utf8')
const load = name => { const c = {}; vm.createContext(c); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/'+name),'utf8'), c); return c }
const Proton = load('Proton.js')
const NAMES = ['probeProcess','nmProcess','statusProcess','infoProcess','actionProcess','configProcess','countriesProcess','citiesProcess']

// Production ProtonService function bodies run against inert fake processes.
// launch=false models Quickshell failing to launch: running never becomes true
// and no exited signal is ever emitted. Nothing is executed.
function service(launch) {
  const queue = [], done = [], killSwitch = [], detached = []
  const s = { Proton, Date, active:true, panelOpen:false, phase:'', installed:true, account:'signed-in',
    nm:{ok:true,at:1,match:'none'}, cli:{ok:true,at:1,state:'disconnected'}, action:'', error:'', message:'',
    clock:Date.now(), generation:0, countries:[], countriesError:'', cities:{}, citiesError:'',
    queue, done, killSwitch, detached,
    Qt:{callLater(f){queue.push(f)}}, launchCheck:{restart(){}},
    Quickshell:{execDetached(argv){detached.push(argv)}},
    actionDone(...a){done.push(a)}, killSwitchRead(v){killSwitch.push(v)}, observed(){} }
  for (const name of NAMES) {
    let running = false
    s[name] = {startedAt:0, timeoutMs:0, revision:-1, handledExit:true, command:[], code:''}
    Object.defineProperty(s[name], 'running', {get(){ return running }, set(v){ running = launch === false ? false : v }})
  }
  Object.defineProperty(s,'busy',{get(){ return s.actionProcess.running || s.configProcess.running }})
  Object.defineProperty(s,'status',{get(){ return Proton.buildStatus({installed:s.installed, action:s.action, nm:s.nm, cli:s.cli,
    now:Date.now(), phase:s.phase, error:s.error, message:s.message, account:s.account}) }})
  const re = /^  function (\w+)\(([^)]*)\) \{/gm; let m
  while ((m=re.exec(source))) {
    let start=re.lastIndex, depth=1, end=start
    while(depth && end<source.length) { if(source[end]==='{') depth++; if(source[end]==='}') depth--; end++ }
    s[m[1]]=new Function(...m[2].split(',').map(x=>x.trim()).filter(Boolean), 'with(this){'+source.slice(start,end-1)+'}')
  }
  s.root = s
  s.flush = () => { while (queue.length) queue.shift().call(s) }
  return s
}

// ---- sign-in: fixed literal, `--` ends options before the typed username -----
{
  const s = service(true); s.signIn()
  assert.deepEqual(s.detached, [['omarchy-launch-floating-terminal-with-presentation',
    "read -rp 'Proton username: ' u && protonvpn signin -- \"$u\""]])
  assert.match(source, /protonvpn signin -- \\"\$u\\""\]\)/, 'sign-in command stays a fixed literal')
}

// ---- launch failure: commands that never start still finish ------------------
assert.equal(typeof service(true).checkLaunches, 'function', 'launch check missing')
{ // Connect that never launches ends the action with a clear error.
  const s = service(false)
  assert.equal(s.connect({kind:'country', country:'CH'}), true)
  assert.equal(s.action, 'connect')
  s.checkLaunches(); s.flush()
  assert.equal(s.action, ''); assert.equal(s.error, 'Could not run protonvpn')
  assert.deepEqual(s.done[0], ['connect', false, 'Could not run protonvpn'])
  assert.equal(s.cli.ok, false); assert.equal(s.cli.state, 'unknown')
  assert.equal(s.status.state === 'connecting', false, 'no longer connecting')
  const count = s.done.length; s.checkLaunches(); s.flush()
  assert.equal(s.done.length, count, 'a launch failure is reported once')
}
{ // Disconnect likewise.
  const s = service(false); s.disconnect(); s.checkLaunches(); s.flush()
  assert.equal(s.action, ''); assert.deepEqual(s.done[0], ['disconnect', false, 'Could not run protonvpn'])
}
{ // Kill-switch read that never launches reports '' (which refuses the switch).
  const s = service(false); assert.equal(s.readKillSwitch(), true); s.checkLaunches(); s.flush()
  assert.deepEqual(s.killSwitch, [''])
}
{ // Observations and lists become unknown/failed; nothing stays busy.
  const s = service(false); s.refresh(); s.refreshAccount(); s.loadCountries(true); s.loadCities('CH')
  s.checkLaunches(); s.flush()
  assert.equal(s.nm.ok, false); assert.equal(s.cli.ok, false); assert.equal(s.cli.state, 'unknown')
  assert.equal(s.account, 'unknown')
  assert.equal(s.countriesError, 'Could not run protonvpn'); assert.equal(s.citiesError, 'Could not run protonvpn')
  assert.equal(s.busy, false); assert.equal(s.action, '')
}
{ // Running, exited and abandoned processes are never reported as launch failures.
  const s = service(true); s.connect({kind:'fastest'}); s.checkLaunches(); s.flush()
  assert.equal(s.action, 'connect'); assert.deepEqual(s.done, [])
  s.actionProcess.handledExit = true; s.actionProcess.running = false; s.checkLaunches(); s.flush()
  assert.deepEqual(s.done, [])
  const k = service(false); k.readKillSwitch(); k.configProcess.revision = -1; k.checkLaunches(); k.flush()
  assert.deepEqual(k.killSwitch, [])
}
console.log('proton service sign-in command and launch-failure tests passed')
