const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const panel = fs.readFileSync(path.join(__dirname,'../../plugin/BarWidget.qml'),'utf8')
const load = name => { const c = {}; vm.createContext(c); vm.runInContext(fs.readFileSync(path.join(__dirname,'../../plugin/'+name),'utf8'), c); return c }
const Model = load('Model.js'), Proton = load('Proton.js'), Traffic = load('Traffic.js')
const binding = name => { const m = panel.match(new RegExp('readonly property \\w+ ' + name + ': ([^\\n]+)')); assert.ok(m, name + ' binding missing'); return m[1] }
const block = name => { const m = panel.match(new RegExp('readonly property \\w+ ' + name + ': \\{([\\s\\S]*?)\\n  \\}')); assert.ok(m, name + ' block missing'); return m[1] }

// The shield comes from the service's combined state; fixtures without it keep WireGuard behavior.
const info = new Function('service', 'return ' + binding('shieldInfo'))
assert.equal(info({status:{state:'connected'}}).state, 'connected')
assert.equal(info({status:{state:'failed'}}).state, 'failed')
assert.equal(info({status:{state:'disabled'}, shield:{state:'conflict', vpn:''}}).state, 'conflict')
const shieldState = shieldInfo => new Function('root', 'return ' + binding('shieldState'))({shieldInfo})
const color = (shieldState, ...rest) => new Function('root','success','warning','errorColor','dim', block('stateColor'))({shieldState}, ...rest)
const glyph = shieldState => new Function('root', 'return ' + binding('stateGlyph'))({shieldState})
for (const [state, expected] of [['connected','green'],['connecting','yellow'],['failed','red'],['enabled-unverified','red'],['conflict','red'],['unknown','muted'],['disabled','muted'],['paused','muted']]) {
  assert.equal(color(state,'green','yellow','red','muted'), expected, state)
  assert.equal(glyph(state), String.fromCodePoint(state === 'connected' ? 0xF0565 : 0xF0498))
}
// Unknown Proton status can never produce the green check shield.
for (const wg of ['disabled','unknown']) {
  const s = shieldState(info({status:{state:wg, enabled: wg === 'disabled' ? false : null}, shield:Proton.shield({state:wg}, {state:'unknown'}, false)}))
  assert.notEqual(s, 'connected')
}
// Traffic is displayed for whichever VPN the shield shows as connected.
const traffic = service => new Function('root', 'service', 'return ' + binding('traffic'))({shieldState: shieldState(info(service))}, service)
assert.equal(traffic({status:{state:'connected'}, traffic:{rx:1}}).rx, 1)
assert.equal(traffic({status:{state:'disabled'}, shield:{state:'connected',vpn:'Proton'}, traffic:{rx:2}}).rx, 2)
assert.equal(traffic({status:{state:'connected'}, shield:{state:'conflict'}, traffic:{rx:3}}), null)

// Tooltip names the active VPN and server; omits Proton for fixtures without it.
const tip = new Function('root','service','Model','Proton','Traffic', block('tooltipText'))
const proton = {state:'connected', server:'CH#12', location:'Zurich, Switzerland', load:'34%', protocol:'wireguard', phase:'', error:''}
const wg = {state:'disabled', enabled:false}
const withProton = tip({shieldInfo:Proton.shield(wg, proton, false), shieldState:'connected', traffic:null}, {status:wg, protonStatus:proton}, Model, Proton, Traffic)
assert.match(withProton, /Active VPN: Proton VPN/); assert.match(withProton, /CH#12 \(Zurich, Switzerland\)/)
const without = tip({shieldInfo:{state:'connected',vpn:'WireGuard'}, shieldState:'connected', traffic:null}, {status:{state:'connected'}}, Model, Proton, Traffic)
assert.doesNotMatch(without, /Proton/); assert.match(without, /WireGuard: connected/)
assert.match(panel, /tooltipText: root.tooltipText/)

// Proton section and inline switch confirmation.
assert.match(panel, /PanelSectionHeader \{ text: "PROTON VPN"/)
// WireGuard profiles come before the Proton section, which precedes backend maintenance.
assert.ok(panel.indexOf('text: "PROFILES"') < panel.indexOf('text: "PROTON VPN"'), 'WireGuard profiles above Proton')
assert.ok(panel.indexOf('text: "PROTON VPN"') < panel.indexOf('text: "BACKEND MAINTENANCE"'), 'Proton above maintenance')
const protonVisible = panel.match(/visible: ([^\n]+)\n[^\n]*\n[^\n]*\n\s+PanelSectionHeader \{ text: "PROTON VPN"/)
assert.ok(protonVisible, 'Proton section visibility binding')
assert.equal(new Function('service','return '+protonVisible[1])({status:{}}), false, 'fixtures without Proton hide the section')
assert.equal(new Function('service','return '+protonVisible[1])({status:{}, protonStatus:{installed:false,state:'absent'}}), true)
const confirm = panel.match(/visible: ([^\n]+)\n[^\n]*\n[^\n]*\n\s+PanelSectionHeader \{ text: "CONFIRM VPN SWITCH"/)
assert.ok(confirm, 'inline switch confirmation')
assert.equal(new Function('service','return '+confirm[1])({}), false)
assert.equal(new Function('service','return '+confirm[1])({switchRequest:{target:'proton'}}), true)
assert.match(panel, /regular connection/)
assert.match(panel, /onClicked: service.confirmSwitch\(\)/)
assert.match(panel, /onClicked: service.cancelSwitch\(\)/)
assert.match(panel, /onClicked: service.protonSignIn\(\)/)
assert.match(panel, /onClicked: service.disconnectProton\(\)/)
for (const kind of ['fastest','random','p2p','securecore','tor']) assert.match(panel, new RegExp('kind: "' + kind + '"'))
assert.match(panel, /kind: "country", country: /)
assert.match(panel, /kind: "city", country: /)
assert.match(panel, /kind: "server", server: /)
assert.match(panel, /Proton.validServerName\(/)
assert.match(panel, /service.loadProtonCountries\(/)
assert.match(panel, /service.loadProtonCities\(/)

// Selecting a WireGuard profile that needs confirmation keeps the panel open.
const body = panel.match(/function activateSelected\(\) \{([\s\S]*?)\n  \}/)[1]
let closed = 0
const ctx = {Model, statusKnown:true, selectedIndex:0, locations:[{id:'home',kind:'profile'}],
  service:{busy:false, status:{state:'disabled'}, switchRequest:null, connectLocation(item){ this.switchRequest = {target:'wireguard'} }, disconnect(){}},
  close(){ closed++ }}
new Function('with(this){'+body+'}').call(ctx)
assert.equal(closed, 0)
ctx.service.connectLocation = function() {}; ctx.service.switchRequest = null
new Function('with(this){'+body+'}').call(ctx)
assert.equal(closed, 1)
// Closing the panel drops an unconfirmed switch.
assert.match(panel, /if \(!opened && service.cancelSwitch\) service.cancelSwitch\(\)/)
console.log('proton panel bindings, confirmation and fixture-omission tests passed')
