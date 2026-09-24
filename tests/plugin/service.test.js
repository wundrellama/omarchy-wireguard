const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const source = fs.readFileSync(path.join(__dirname,'../../plugin/Service.qml'),'utf8')
const Model = {}; vm.createContext(Model); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/Model.js'),'utf8'), Model)
const Proton = {}; vm.createContext(Proton); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/Proton.js'),'utf8'), Proton)
// Exercise production function bodies; QML runtime imports are tested separately.
function service() {
  const s = { Model, Proton, Date, active:false, switchPhase:'', switchRequest:null, switchTarget:null, pendingConnection:null, lastConnection:null,
    Qt:{callLater(){}}, protonService:{status:{state:'absent',installed:false}}, status:Model.unknownStatus(), catalog:{locations:[]},
    disconnectRecovery:false, lastStatusAt:0, closedRefreshIntervalSec:30, busy:false, panelOpen:false,
    lastError:'', actionError:'', pendingAction:'', actionMessage:'', refreshing:false,
    sawFirstStatus:false, previousState:'', previousPaused:false, failureNotificationShown:false,
    handshakeFailureConfirmationPending:false, importPaths:[], currentUser:'tester', installScriptPath:'/not/executed',
    Quickshell:{execDetached(){throw Error('inactive detached process')}},
    delayedRefresh:{restart(){}}, handshakeFailureNotificationDelay:{restart(){},stop(){}} }
  for (const name of ['statusProcess','listProcess','actionProcess','pickerProcess','installProcess','diagnosticsProcess','clipboardProcess','lastConnectionReader','lastConnectionWriter']) s[name]={running:false}
  const re = /^  function (\w+)\(([^)]*)\) \{/gm; let m
  while ((m=re.exec(source))) {
    let start=re.lastIndex, depth=1, end=start
    // Bodies in this service have balanced braces, including object literals.
    while(depth && end<source.length) { if(source[end]==='{') depth++; if(source[end]==='}') depth--; end++ }
    s[m[1]]=new Function(...m[2].split(',').map(x=>x.trim()).filter(Boolean), 'with(this){'+source.slice(start,end-1)+'}')
  }
  return s
}
const s=service()
for (const [name,args] of [['refresh',[]],['connectLocation',[{id:'x',kind:'profile'}]],['disconnect',[]],['retry',[]],['chooseImport',[false]],['installBackend',[]],['uninstallBackend',[]],['copyDiagnostics',[]],['openGenerator',[]],['notify',['test','test','normal']]]) s[name](...args)
assert.equal(s.statusProcess.running,false)
assert.equal(s.actionProcess.running,false)
assert.equal(s.pickerProcess.running,false)
assert.equal(s.installProcess.running,false)
assert.equal(s.diagnosticsProcess.running,false)
s.applyStatus('{"mode":"connected","enabled":true}')
assert.equal(s.status.state,'connected')
s.applyStatus('broken'); assert.equal(s.status.state,'unknown')
s.applyStatus('{"mode":"connected","enabled":true}')
s.markCliUnavailable('failed command'); assert.equal(s.status.state,'unknown'); assert.notEqual(s.status.enabled,false)
s.applyStatus('{"mode":"connected","enabled":true}'); s.lastStatusAt=Date.now()-400000; s.expireStatus(); assert.equal(s.status.state,'unknown')
s.applyActionOutput('{"ok":false,"error":{"message":"Duplicate profile"}}'); assert.equal(s.actionError,'Duplicate profile')
s.applyActionOutput('broken'); assert.equal(s.status.state,'unknown')
s.applyStatus('{"mode":"connected","enabled":true}'); s.applyActionOutput('{"ok":false,"error":{"message":"Full tunnel required"}}'); assert.equal(s.status.state,'unknown')
s.active=true; s.statusRevision=1; s.applyPoll('{"mode":"connected","enabled":true}', Date.now()-20000, 1); assert.equal(s.status.state,'unknown')
s.applyPoll('{"mode":"connected","enabled":true}', Date.now(), 0); assert.equal(s.status.state,'unknown')
s.applyPoll('{"mode":"connected","enabled":true}', Date.now(), 1); assert.equal(s.status.state,'connected')
const commandService=service(); commandService.active=true; commandService.statusRevision=0
commandService.applyStatus('{"mode":"disabled","enabled":false}')
commandService.connectLocation({id:'named-id',kind:'profile'})
assert.deepEqual(commandService.actionProcess.command,['omarchy-wireguard','connect','--profile','named-id'])
assert.equal(commandService.status.state,'unknown')
commandService.actionProcess.running=false
commandService.applyStatus('{"mode":"disabled","enabled":false}')
commandService.connectLocation({id:'Japan/Tokyo',kind:'city'})
assert.deepEqual(commandService.actionProcess.command,['omarchy-wireguard','connect','Japan/Tokyo'])
commandService.actionProcess.running=false
commandService.applyStatus('{"mode":"disabled","enabled":false}')
commandService.importPaths=['/bundle.zip']; commandService.status.importReview={candidates:['home.conf']}
commandService.submitImportReview({'home.conf':'Personal'})
assert.deepEqual(commandService.actionProcess.command,['omarchy-wireguard','import','/bundle.zip','--labels','{"home.conf":"Personal"}'])
// Bootstrap is explicit, even before the first successful status response.
const bootstrap=service(); bootstrap.active=true
assert.equal(bootstrap.installProcess.command,undefined)
bootstrap.uninstallBackend(); assert.equal(bootstrap.installProcess.running,false)
bootstrap.installBackend()
assert.deepEqual(bootstrap.installProcess.command,['pkexec','/not/executed','tester'])
assert.equal(bootstrap.installProcess.running,true)
assert.equal(bootstrap.status.state,'unknown')
assert.equal(bootstrap.status.enabled,null)
for (const overrides of [{active:false},{busy:true},{installScriptPath:''},{currentUser:''},{installProcess:{running:true}}]) {
  const blocked=service(); Object.assign(blocked,{active:true},overrides)
  blocked.installBackend(); assert.equal(blocked.installProcess.command,undefined)
}
console.log('service tests passed')
