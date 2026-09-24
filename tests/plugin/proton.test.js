const assert = require('node:assert/strict')
const fs = require('node:fs')
const vm = require('node:vm')
const path = require('node:path')
const file = path.join(__dirname, '../../plugin/Proton.js')
assert.ok(fs.existsSync(file), 'Proton model missing')
const P = {}; vm.createContext(P); vm.runInContext(fs.readFileSync(file, 'utf8'), P)
const plain = value => JSON.parse(JSON.stringify(value))

// Output formats pinned from proton-vpn-cli 1.0.3 (commands/server.py, location_discovery.py,
// settings.py, account.py). All account, server and address values are synthetic.
const outdated = 'Server list is outdated, updating... This may take a moment.\n'
{
  assert.deepEqual(plain(P.parseStatus('Status: Disconnected\n')), {ok:true,state:'disconnected',server:'',location:'',load:'',protocol:''})
  const connected = 'Status: Connected\nServer: CH#12 in Zurich, Switzerland\nLoad: 34%\nProtocol: wireguard\n'
  assert.deepEqual(plain(P.parseStatus(connected)), {ok:true,state:'connected',server:'CH#12',location:'Zurich, Switzerland',load:'34%',protocol:'wireguard'})
  assert.equal(P.parseStatus(outdated + connected).server, 'CH#12')
  assert.equal(P.parseStatus('\x1b[1mStatus: Connected\x1b[0m\nServer: \x1b[32mIT#23\x1b[0m in Milan, Italy\nLoad: 5%\nProtocol: wireguard').server, 'IT#23')
  const secure = P.parseStatus('Status: Connected\nServer: CH-US#1 in New York, via Switzerland\nLoad: 7%\nProtocol: wireguard')
  assert.equal(secure.server, 'CH-US#1'); assert.equal(secure.location, 'New York, via Switzerland')
  const noCity = P.parseStatus('Status: Connected\nServer: IS#3 in Iceland\nLoad: 1%\nProtocol: wireguard')
  assert.equal(noCity.location, 'Iceland')
  for (const raw of ['', 'garbage', 'Status: Connected\n', 'Status: Maybe', 'Status: Connected\nServer: $(reboot) in X\nLoad: 1%\nProtocol: wireguard', 'Status: Disconnectedx'])
    assert.equal(P.parseStatus(raw).state, 'unknown', raw)
  assert.equal(P.parseStatus(outdated + 'Status: Disconnected').state, 'disconnected')
}
{
  const raw = outdated + 'Country                           Code\n--------------------------------  ------\nAfghanistan                       AF\nBosnia and Herzegovina            BA\nUnited States                     US\n'
  assert.deepEqual(plain(P.parseCountries(raw)), [{name:'Afghanistan',code:'AF'},{name:'Bosnia and Herzegovina',code:'BA'},{name:'United States',code:'US'}])
  assert.deepEqual(plain(P.parseCountries('Country  Code\n-------  ----\nBad row  usa\nInjected  ;;\n')), [])
  assert.deepEqual(plain(P.filterCountries(P.parseCountries(raw), 'united')).map(c => c.code), ['US'])
  assert.deepEqual(plain(P.filterCountries(P.parseCountries(raw), 'af')).map(c => c.code), ['AF'])
  assert.equal(P.filterCountries(P.parseCountries(raw), '').length, 3)
}
{
  const raw = '\nCities in United States:\nCity            Features\n--------------  ----------\nAshburn         P2P\nAtlanta         P2P, Tor\nNew York        \nSão Paulo       P2P\n\n'
  assert.deepEqual(plain(P.parseCities(raw)), [
    {name:'Ashburn',features:['P2P']},{name:'Atlanta',features:['P2P','Tor']},{name:'New York',features:[]},{name:'São Paulo',features:['P2P']}])
  assert.deepEqual(plain(P.parseCities(outdated + '\nCities in Switzerland:\nCity    Features\n------  ----------\nZurich  P2P, Tor\n')), [{name:'Zurich',features:['P2P','Tor']}])
  assert.deepEqual(plain(P.parseCities('City  Features\n----  --------\n-rf   P2P\n')), [])
}
{
  assert.equal(P.parseAccount("Account: 'someone@example.invalid'\n"), 'signed-in')
  assert.equal(P.parseAccount("Account: 'None'\n"), 'signed-out')
  assert.equal(P.parseAccount(''), 'unknown')
  assert.equal(P.parseAccount("Account: ''"), 'unknown')
  assert.equal(P.accountFromError('Error: Authentication required. Please sign in'), 'signed-out')
  assert.equal(P.accountFromError('Error: network down'), 'unknown')
}
{
  const table = '\nCurrent configuration\nSetting                  Value\n-----------------------  ------------\nnetshield                malware-only\nkill-switch              off\nport-forwarding          off\n'
  assert.equal(P.parseKillSwitch(table), 'off')
  assert.equal(P.parseKillSwitch(table.replace('kill-switch              off', 'kill-switch              standard')), 'standard')
  assert.equal(P.parseKillSwitch(table.replace('kill-switch              off', 'kill-switch              advanced')), 'advanced')
  assert.equal(P.parseKillSwitch('Setting  Value\nnetshield  off\n'), '')
  assert.equal(P.parseKillSwitch(table + 'kill-switch  standard\n'), '')
}
{
  const ok = 'ProtonVPN CH#12:4bd6ef4f-ca1a-4756-b9d2-55678bee6008:wireguard:proton0:activated\nWi-Fi:1bd6ef4f-ca1a-4756-b9d2-55678bee6008:802-11-wireless:wlan0:activated\n'
  assert.deepEqual(plain(P.parseActive(ok)), {ok:true,match:'one',server:'CH#12',activated:true})
  assert.equal(P.parseActive(ok.replace(':activated\nWi', ':activating\nWi')).activated, false)
  assert.equal(P.parseActive('Wi-Fi:x:802-11-wireless:wlan0:activated\n').match, 'none')
  assert.equal(P.parseActive('').match, 'none')
  assert.equal(P.parseActive(ok + ok.split('\n')[0]).match, 'ambiguous')
  assert.equal(P.parseActive('ProtonVPN Home:x:802-11-wireless:wlan0:activated').match, 'ambiguous')
  assert.equal(P.parseActive('ProtonVPN CH#12:x:wireguard:owg-home:activated').match, 'ambiguous')
  assert.equal(P.parseActive('ProtonVPN CH#12:x:vpn:proton0:activated').match, 'ambiguous')
  // A malformed row that still mentions Proton is ambiguous, never skipped.
  assert.equal(P.parseActive(ok + 'ProtonVPN IT#1:x:wireguard:proton0\n').match, 'ambiguous', 'short Proton row')
  assert.equal(P.parseActive(ok + 'Other:x:wireguard:proton0:activated:extra\n').match, 'ambiguous', 'long proton0 row')
  assert.equal(P.parseActive('ProtonVPN CH#12:x:wireguard:proton0:activated:extra\n').match, 'ambiguous')
  assert.equal(P.parseActive('Wi-Fi:x:802-11-wireless:wlan0\n').match, 'none', 'unrelated malformed rows still ignored')
}
{
  for (const code of ['US','CH','GB']) assert.equal(P.validCountryCode(code), true)
  for (const code of ['us','USA','U','-U','U$','',null,'U\n']) assert.equal(P.validCountryCode(code), false, String(code))
  for (const name of ['IT#23','CH-US#1','US-CA#148','JP-FREE#1','FR#13-TOR','US-CO#21-TOR','DE#1262']) assert.equal(P.validServerName(name), true, name)
  for (const name of ['it#23','IT23','IT#','#23','--help','IT#23;reboot','IT#23 ','IT#123456','CH-US#1-FOO','$(x)#1','IT#23\n','A'.repeat(40)]) assert.equal(P.validServerName(name), false, name)
  for (const city of ['New York','São Paulo','Bogotá',"Saint John's",'Washington, D.C.']) assert.equal(P.validCity(city), true, city)
  for (const city of ['','-rf','--help',' Zurich','Zurich\n','Zu\u0007rich','A'.repeat(65),'$(reboot)','x;y','a`b','a|b','a>b']) assert.equal(P.validCity(city), false, JSON.stringify(city))
}
{
  const args = choice => plain(P.connectArgs(choice))
  assert.deepEqual(args({kind:'fastest'}), ['connect'])
  assert.deepEqual(args({kind:'random'}), ['connect','--random'])
  assert.deepEqual(args({kind:'p2p'}), ['connect','--p2p'])
  assert.deepEqual(args({kind:'securecore'}), ['connect','--securecore'])
  assert.deepEqual(args({kind:'tor'}), ['connect','--tor'])
  assert.deepEqual(args({kind:'country',country:'CH'}), ['connect','--country','CH'])
  assert.deepEqual(args({kind:'city',country:'US',city:'New York'}), ['connect','--city','New York'])
  assert.deepEqual(args({kind:'server',server:'CH-US#1'}), ['connect','CH-US#1'])
  for (const bad of [null,{},{kind:'shell'},{kind:'country',country:'ch'},{kind:'country',country:'--tor'},{kind:'city',city:'-x'},{kind:'server',server:'--random'},{kind:'server',server:'IT#1 --tor'}])
    assert.equal(P.connectArgs(bad), null, JSON.stringify(bad))
  assert.equal(P.choiceLabel({kind:'city',city:'New York'}), 'New York')
  assert.equal(P.choiceLabel({kind:'securecore'}), 'Secure Core')
}
{
  const cliError = 'Server list is outdated, updating... This may take a moment.\nUsage: protonvpn connect [OPTIONS] [SERVER_NAME]\nTry \'protonvpn connect --help\' for help.\n\n\x1b[31mError: Invalid country code \'XX\'. Please use a valid country code.\x1b[0m\n'
  assert.equal(P.errorMessage(cliError, 'fallback'), "Invalid country code 'XX'. Please use a valid country code.")
  assert.equal(P.errorMessage('', 'Proton connect failed'), 'Proton connect failed')
  assert.equal(P.errorMessage('Connection failed. Try again.\u0000\u0007', 'x'), 'Connection failed. Try again.')
  assert.ok(P.errorMessage('Error: ' + 'x'.repeat(900), 'x').length <= 300)
}
{
  const wg = (state, enabled) => ({state, enabled})
  const p = (state, extra={}) => Object.assign({state, phase:'', error:'', server:'CH#12', location:'Zurich, Switzerland'}, extra)
  const shield = (...a) => plain(P.shield(...a))
  // Fixtures without Proton keep the existing WireGuard mapping unchanged.
  for (const state of ['connected','connecting','failed','enabled-unverified','disabled','unknown','paused'])
    assert.equal(P.shield(wg(state, state !== 'disabled'), undefined, false).state, state)
  assert.equal(P.shield(wg('connected', true), null, false).vpn, 'WireGuard')
  assert.deepEqual(shield(wg('disabled', false), p('connected'), false), {state:'connected',vpn:'Proton',label:'Proton VPN connected'})
  assert.equal(P.shield(wg('disabled', false), p('connecting'), false).state, 'connecting')
  assert.equal(P.shield(wg('disabled', false), p('disconnecting'), false).state, 'connecting')
  assert.equal(P.shield(wg('disabled', false), p('disconnected', {error:'Connection failed.'}), false).state, 'failed')
  assert.equal(P.shield(wg('disabled', false), p('unknown'), false).state, 'unknown')
  assert.equal(P.shield(wg('disabled', false), p('disconnected'), false).state, 'disabled')
  assert.equal(P.shield(wg('disabled', false), p('absent'), false).state, 'disabled')
  // Proton status unknown never makes anything green by itself.
  assert.notEqual(P.shield(wg('unknown', null), p('unknown'), false).state, 'connected')
  // WireGuard remains authoritative for its own fail-closed tunnel.
  assert.equal(P.shield(wg('connected', true), p('unknown'), false).state, 'connected')
  assert.equal(P.shield(wg('connected', true), p('disconnected', {error:'aborted'}), false).state, 'connected')
  // Both active outside a switch is a conflict, never green.
  assert.equal(P.shield(wg('connected', true), p('connected'), false).state, 'conflict')
  assert.equal(P.shield(wg('failed', true), p('connected'), false).state, 'conflict')
  assert.equal(P.shield(wg('unknown', null), p('connected'), true).state, 'conflict')
  // Unknown never renders green: Proton is green only when WireGuard is known
  // disabled or known absent (backend not installed); otherwise muted unknown.
  assert.deepEqual(shield(wg('unknown', null), p('connected'), false), {state:'unknown',vpn:'',label:'WireGuard status unknown; Proton VPN connected'})
  assert.equal(P.shield(wg('unknown', null), p('connected'), false, false).state, 'unknown')
  assert.deepEqual(shield(wg('unknown', null), p('connected'), false, true), {state:'connected',vpn:'Proton',label:'Proton VPN connected'})
  assert.equal(P.shield(wg('unknown', null), p('connected'), true, true).state, 'conflict', 'recovery still wins over absent')
  assert.equal(P.shield(wg('unknown', null), p('connecting'), false).state, 'connecting')
  // A switch in progress is amber through the unprotected moment.
  assert.equal(P.shield(wg('disabled', false), p('disconnected', {phase:'wg-wait'}), false).state, 'connecting')
  assert.equal(P.shield(wg('connected', true), p('connected', {phase:'proton-disconnect'}), false).state, 'connecting')
  const tip = P.tooltip(P.shield(wg('disabled', false), p('connected', {load:'34%', protocol:'wireguard'}), false), wg('disabled', false), p('connected', {load:'34%', protocol:'wireguard'}))
  assert.match(tip, /Proton VPN: connected/); assert.match(tip, /CH#12/); assert.match(tip, /Zurich, Switzerland/)
  assert.match(P.tooltip(P.shield(wg('connected', true), p('connected'), false), wg('connected', true), p('connected')), /Conflict/)
  assert.doesNotMatch(P.tooltip(P.shield(wg('disabled', false), undefined, false), wg('disabled', false), undefined), /Proton/)
}
{
  const active = (state, enabled) => ({state, enabled})
  assert.equal(P.wireGuardActive(active('connected', true), false), true)
  assert.equal(P.wireGuardActive(active('failed', true), false), true)
  assert.equal(P.wireGuardActive(active('disabled', false), false), false)
  assert.equal(P.wireGuardActive(active('unknown', null), true), true)
  assert.equal(P.wireGuardActive(active('unknown', null), false), false)
  assert.equal(P.wireGuardReleased({state:'disabled',enabled:false}, 2000, 1000), true)
  assert.equal(P.wireGuardReleased({state:'disabled',enabled:false}, 1000, 1000), false, 'observation must follow the disconnect')
  assert.equal(P.wireGuardReleased({state:'unknown',enabled:null}, 2000, 1000), false)
  assert.equal(P.wireGuardReleased({state:'connecting',enabled:true}, 2000, 1000), false)
}
{
  const s = (overrides={}) => Object.assign({installed:true, action:'', nm:{ok:true,at:1000,match:'none',server:'',activated:false}, cli:{ok:true,at:1000,state:'disconnected'}, now:2000}, overrides)
  assert.equal(P.deriveState(s({installed:false})), 'absent')
  assert.equal(P.deriveState(s()), 'disconnected')
  assert.equal(P.deriveState(s({action:'connect'})), 'connecting')
  assert.equal(P.deriveState(s({action:'disconnect'})), 'disconnecting')
  assert.equal(P.deriveState(s({nm:{ok:true,at:1000,match:'one',server:'CH#12',activated:true}})), 'connected')
  assert.equal(P.deriveState(s({nm:{ok:true,at:1000,match:'one',server:'CH#12',activated:false}})), 'connecting')
  assert.equal(P.deriveState(s({nm:{ok:true,at:1000,match:'ambiguous'}})), 'unknown')
  assert.equal(P.deriveState(s({nm:{ok:false,at:1000}})), 'unknown')
  assert.equal(P.deriveState(s({now:40000})), 'unknown', 'stale observations are unknown')
  assert.equal(P.deriveState(s({nm:{ok:true,at:0,match:'none'}})), 'unknown', 'never observed is unknown')
  // Proton says connected but no exact NM tunnel: contradiction, not disconnected.
  assert.equal(P.deriveState(s({cli:{ok:true,at:1500,state:'connected'}})), 'unknown')
  // Proton installed state not yet known does not hide a real tunnel.
  assert.equal(P.deriveState(s({installed:null, nm:{ok:true,at:1000,match:'one',server:'CH#12',activated:true}})), 'connected')
}
{
  const shield = {state:'connected', vpn:'WireGuard'}
  assert.equal(P.trafficProfile({state:'connected',currentProfile:'home'}, shield), 'home')
  assert.equal(P.trafficProfile({state:'connected',currentProfile:'home'}, {state:'conflict',vpn:''}), '')
  assert.equal(P.trafficProfile({state:'disabled',currentProfile:''}, {state:'connected',vpn:'Proton'}), '@proton')
  assert.equal(P.trafficProfile({state:'disabled',currentProfile:''}, {state:'connecting',vpn:'Proton'}), '')
  assert.equal(P.trafficProfile({state:'unknown'}, {state:'unknown',vpn:''}), '')
}
{
  assert.match(P.summary({installed:false, state:'absent'}), /not installed/)
  assert.match(P.summary({installed:null, state:'unknown'}), /Checking/)
  assert.match(P.summary({installed:true, state:'disconnected', account:'signed-out'}), /Signed out/)
  assert.match(P.summary({installed:true, state:'unknown', account:'signed-in'}), /unknown/i)
  assert.equal(P.summary({installed:true, state:'connected', account:'signed-in', server:'CH#12', location:'Zurich, Switzerland', load:'34%', protocol:'wireguard'}),
    'Connected · CH#12 · Zurich, Switzerland · Load 34% · wireguard')
  assert.equal(P.summary({installed:true, state:'disconnected', account:'signed-in'}), 'Disconnected · signed in')
  assert.equal(P.summary(undefined), '')
}
console.log('proton parsers, validation, arguments, state and shield tests passed')
