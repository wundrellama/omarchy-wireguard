const assert = require('node:assert/strict'); const fs = require('node:fs'); const vm = require('node:vm');
const path = require('node:path');
const file = path.join(__dirname, '../../plugin/Traffic.js');
assert.ok(fs.existsSync(file), 'traffic model missing');
const T = {}; vm.createContext(T); vm.runInContext(fs.readFileSync(file, 'utf8'), T);
const sample = (time, rx, tx, extra={}) => JSON.stringify({ok:true,profile:'home',uuid:'uuid',interface:'owg-1234',ifindex:42,time,rx,tx,...extra});
const first = T.accept(null, sample(10, 1000, 2000), 'home');
assert.equal(first.rx,1000); assert.equal(first.down,null);
const next = T.accept(first, sample(12, 2024, 4048), 'home');
assert.equal(next.down,512); assert.equal(next.up,1024);
assert.equal(T.formatBytes(1024),'1.0 KiB'); assert.equal(T.formatBytes(null),'—');
for (const raw of ['bad', '{}', 'null', sample(13,-1,2), sample(13,'3',2), sample(13,2,3,{ok:false}), sample(13,2,3,{profile:'other'})])
  assert.equal(T.accept(next,raw,'home'),null);
for (const raw of [sample(14,2,3),sample(14,3000,5000,{ifindex:43}),sample(14,3000,5000,{uuid:'different'}),sample(14,3000,5000,{interface:'owg-new'}),sample(25,3000,5000)])
  assert.equal(T.accept(next,raw,'home').down,null);
assert.equal(T.accept(next,sample(12,3000,5000),'home'),null);
assert.equal(T.accept(next,sample(11,3000,5000),'home'),null);
assert.equal(T.accept(null,sample(14,3000,5000),''),null); // disconnected must reject
// Proton mode accepts only the exact proton0 interface under the reserved key.
const proton = (time, rx, tx, extra={}) => JSON.stringify({ok:true,profile:'@proton',uuid:'uuid',interface:'proton0',ifindex:9,time,rx,tx,...extra});
const p1 = T.accept(null, proton(10, 100, 200), '@proton'); assert.equal(p1.rx, 100);
assert.equal(T.accept(p1, proton(11, 612, 712), '@proton').down, 512);
assert.equal(T.accept(null, proton(10, 1, 2, {interface:'proton1'}), '@proton'), null);
assert.equal(T.accept(null, proton(10, 1, 2, {interface:'owg-1234'}), '@proton'), null);
assert.equal(T.accept(null, sample(10, 1, 2, {interface:'proton0'}), 'home'), null);
assert.equal(typeof T.summary,'function');
assert.equal(T.summary(null),'Traffic unavailable');
assert.match(T.summary(next),/↓ 512 B\/s.*↑ 1.0 KiB\/s/);
const panel = fs.readFileSync(path.join(__dirname,'../../plugin/BarWidget.qml'),'utf8');
assert.match(panel,/Traffic.summary\(root.traffic\)/);
assert.match(panel,/INTERFACE TRAFFIC/);
const service = fs.readFileSync(path.join(__dirname,'../../plugin/Service.qml'),'utf8');
assert.match(service,/TrafficService/);
console.log('traffic deltas, resets, missing, formats and UI bindings passed');
