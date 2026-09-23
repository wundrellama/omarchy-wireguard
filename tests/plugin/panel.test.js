const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const panel = fs.readFileSync(path.join(__dirname,'../../plugin/BarWidget.qml'),'utf8')
const service = fs.readFileSync(path.join(__dirname,'../../plugin/Service.qml'),'utf8')
assert.match(panel,/property var serviceOverride: null/)
assert.match(panel,/readonly property var service: serviceOverride \|\| liveService/)
assert.match(panel,/id: liveService\s+active: root.serviceOverride === null/)
assert.match(panel,/Internet exit/)
assert.match(panel,/Display label/)
assert.match(panel,/row.location.label/)
assert.doesNotMatch(panel,/Import \/ replace|Pause 10 min|rowIndex === 0 &&|firstRowDisconnects/)
assert.doesNotMatch(service,/replaceImport|notify-send|VPN protection resumed/)
assert.match(panel,/status.state !== "unknown"/)
// Exercise the production keyboard action body against filtered selections.
const vm = require('node:vm')
const Model = {}; vm.createContext(Model); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/Model.js'),'utf8'), Model)
const body = panel.match(/function activateSelected\(\) \{([\s\S]*?)\n  \}/)[1]
const calls = []
const ctx = {Model, statusKnown:true, locations:[{id:'other',kind:'profile',current:false,target:false}],selectedIndex:0,
  service:{busy:false,status:{state:'connected'},disconnect(){calls.push('disconnect')},connectLocation(item){calls.push(item.id)}},close(){}}
const activate = new Function('with(this){'+body+'}')
activate.call(ctx); assert.deepEqual(calls,['other'])
ctx.locations=[{id:'active',current:true}]; activate.call(ctx); assert.deepEqual(calls,['other','disconnect'])
ctx.statusKnown=false; activate.call(ctx); assert.equal(calls.length,2)
ctx.statusKnown=true; ctx.service.busy=true; activate.call(ctx); assert.equal(calls.length,2)
// Evaluate the actual bootstrap section/button bindings, not a replacement UI.
// Bootstrap actions must wrap: the longer repair label overflows a fixed Row.
assert.match(panel,/Flow \{\s+width: parent.width\s+spacing: Style.space\(6\)\s+Button \{ visible: !root.statusKnown/)
const setup=panel.match(/Column \{\s+visible: ([^\n]+)\s+width: parent.width\s+spacing: Style.space\(8\)\s+PanelSectionHeader \{ text: "GET STARTED"/)[1]
const install=panel.match(/Button \{ visible: ([^;]+); enabled: ([^;]+);[^\n]+onClicked: service.installBackend\(\)/)
const bootstrap={statusKnown:false,service:{status:{installed:null,setupRequired:false},busy:false,active:true,installScriptPath:'/not/executed',currentUser:'tester'}}
const evaluate=expression=>new Function('root','service','return '+expression)(bootstrap,bootstrap.service)
assert.equal(evaluate(setup),true)
assert.equal(evaluate(install[1]),true)
assert.equal(evaluate(install[2]),true)
bootstrap.service.currentUser=''; assert.equal(evaluate(install[2]),false)
bootstrap.service.currentUser='tester'; bootstrap.service.busy=true; assert.equal(evaluate(install[2]),false)
// Sequential batches must submit only the exact current candidate source names.
const reviewContext={Model,statusKnown:true,reviewValues:{},service:{status:{importReview:{candidates:['home.conf']}},submitImportReview(labels){this.submitted=labels}}}
for (const name of ['setReviewValue','submitReview','reviewComplete']) {
  const body=panel.match(new RegExp('function '+name+'\\(([^)]*)\\) \\{([\\s\\S]*?)\\n  \\}'))
  reviewContext[name]=new Function(...body[1].split(',').map(x=>x.trim()).filter(Boolean),'with(this){'+body[2]+'}')
}
reviewContext.setReviewValue('home.conf','Home')
reviewContext.submitReview(); assert.deepEqual(reviewContext.service.submitted,{'home.conf':'Home'})
reviewContext.service.status.importReview={candidates:[{source_name:'travel.conf'}]}
reviewContext.setReviewValue('travel.conf','Travel')
reviewContext.submitReview(); assert.deepEqual(reviewContext.service.submitted,{'travel.conf':'Travel'})
const reviewVisible=panel.match(/visible: ([^\n]*service.status.importReview[^\n]*)/)[1]
for (const importReview of [{},undefined,null,{ambiguous:false},{ambiguous:true}]) {
  const actual=new Function('service','return '+reviewVisible)({status:{importReview}})
  assert.equal(actual,importReview?.ambiguous === true)
}
// The reset key is stable across status polling, but changes for a new batch.
const batchBinding=panel.match(/readonly property string reviewBatchKey: ([^\n]+)/)
assert.ok(batchBinding,'review batch reset binding exists')
const batchKey=status=>new Function('service','return '+batchBinding[1])(status)
const firstBatch={importPaths:['/home.zip'],status:{importReview:{candidates:['home.conf']}}}
const key=batchKey(firstBatch)
assert.equal(batchKey(JSON.parse(JSON.stringify(firstBatch))),key)
assert.notEqual(batchKey({importPaths:['/travel.zip'],status:{importReview:{candidates:['travel.conf']}}}),key)
assert.match(panel,/onReviewBatchKeyChanged: reviewValues = \(\{\}\)/)
console.log('panel contract and selection tests passed')
// Selecting a file must restore the panel dismissed by the external chooser.
const returned = panel.match(/function onImportSelectionFinished\(\) \{([^}]+)\}/)
assert.ok(returned, 'picker completion must reopen the import review panel')
let reopened = 0
new Function('root', returned[1])({open(){reopened++}})
assert.equal(reopened, 1)
// Shields share the existing status palette; only connected gets a check mark.
const glyph = panel.match(/readonly property string stateGlyph: ([^\n]+)/)
assert.ok(glyph, 'status indicator uses a shield glyph')
const colorBody = panel.match(/readonly property color stateColor: \{([\s\S]*?)\n  \}/)[1]
for (const [state, color] of [['connected','green'],['connecting','yellow'],['failed','red'],['enabled-unverified','red'],['disabled','muted'],['unknown','muted'],['paused','muted']]) {
  const service = {status:{state}}
  assert.equal(new Function('service', 'return '+glyph[1])(service),
    String.fromCodePoint(state === 'connected' ? 0xF0565 : 0xF0498))
  assert.equal(new Function('service','success','warning','errorColor','dim',colorBody)(service,'green','yellow','red','muted'),color)
}
assert.match(panel, /text: root.stateGlyph\s+foreground: root.stateColor/)
assert.match(panel, /text: root.stateGlyph\s+color: root.stateColor/)
