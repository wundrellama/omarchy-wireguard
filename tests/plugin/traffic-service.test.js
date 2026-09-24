const assert = require('node:assert/strict'), fs = require('node:fs'), vm = require('node:vm'), path = require('node:path');
const file = path.join(__dirname,'../../plugin/TrafficService.qml');
assert.ok(fs.existsSync(file),'traffic service missing');
const source = fs.readFileSync(file,'utf8');
const Traffic = {}; vm.createContext(Traffic); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/Traffic.js'),'utf8'),Traffic);
const ctx = {Traffic,profile:'home',generation:3,traffic:null};
const body = source.match(/function applySample\(([^)]*)\) \{([\s\S]*?)\n  \}/);
assert.ok(body); const apply = new Function(...body[1].split(','), 'with(this){'+body[2]+'}');
const raw = JSON.stringify({ok:true,profile:'home',uuid:'x',interface:'owg-test',ifindex:1,time:10,rx:50,tx:60});
apply.call(ctx,raw,2,'home'); assert.equal(ctx.traffic,null);
apply.call(ctx,raw,3,'other'); assert.equal(ctx.traffic,null);
apply.call(ctx,raw,3,'home'); assert.equal(ctx.traffic.rx,50);
ctx.profile=''; ctx.traffic=null; apply.call(ctx,raw,3,'home'); assert.equal(ctx.traffic,null);
const service = fs.readFileSync(path.join(__dirname,'../../plugin/Service.qml'),'utf8');
const binding = service.match(/profile: ([^\n]+)/)[1];
const Proton = {}; vm.createContext(Proton); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/Proton.js'),'utf8'),Proton);
for (const state of ['unknown','disabled','connecting','failed','connected']) {
  for (const active of [true,false]) {
    const status = {state,currentProfile:'home',enabled:state !== 'disabled'};
    const root = {active,status,shield:Proton.shield(status, undefined, false)};
    assert.equal(new Function('root','Proton','return '+binding)(root,Proton),active && state === 'connected' ? 'home' : '');
  }
}
// Proton: exact '@proton' mode only when Proton alone is connected; conflict samples nothing.
const sampled = (wg, proton) => new Function('root','Proton','return '+binding)({active:true,status:wg,shield:Proton.shield(wg,proton,false)},Proton);
assert.equal(sampled({state:'disabled',enabled:false}, {state:'connected'}), '@proton');
assert.equal(sampled({state:'disabled',enabled:false}, {state:'connecting'}), '');
assert.equal(sampled({state:'disabled',enabled:false}, {state:'unknown'}), '');
assert.equal(sampled({state:'connected',enabled:true,currentProfile:'home'}, {state:'connected'}), '');
const panel = fs.readFileSync(path.join(__dirname,'../../plugin/BarWidget.qml'),'utf8');
const display = panel.match(/readonly property var traffic: ([^\n]+)/)[1];
const shown = service => new Function('root','service','return '+display)({shieldState:(service.shield || service.status).state},service);
assert.equal(shown({status:{state:'connected'}}),null);
assert.equal(shown({status:{state:'disabled'},traffic:{rx:42}}),null);
assert.equal(shown({status:{state:'disabled'},shield:{state:'unknown'},traffic:{rx:42}}),null);
console.log('traffic service rejects old generations, disabled and unknown states; fixture omission safe');
