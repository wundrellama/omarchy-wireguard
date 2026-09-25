const assert = require("node:assert/strict")
const fs = require("node:fs")
const path = require("node:path")
const vm = require("node:vm")

const source = fs.readFileSync(path.join(__dirname, "../../plugin/Model.js"), "utf8")
const model = { String, Number, Math, JSON, Array, Object, isFinite }
vm.createContext(model)
vm.runInContext(source, model)

{
  const status = model.parseStatus(JSON.stringify({
    enabled: true,
    verified: false,
    location: "Tokyo",
    countdown_seconds: 65,
    locations: [
      { id: "la", city: "Los Angeles", country_code: "us" },
      { id: "tyo", city: "Tokyo", country_code: "jp", current: true },
      { id: "lon", city: "London", country_code: "gb", target: true }
    ]
  }))
  assert.equal(status.ok, true)
  assert.equal(status.state, "enabled-unverified")
  assert.equal(status.setupRequired, true, "a pre-v2 backend is surfaced for repair")
  assert.deepEqual(Array.from(status.locations, value => value.id), ["tyo", "lon", "la"])
  assert.equal(model.countdownText(status.countdown), "1m 5s")
  assert.match(model.tooltip(status), /Location: Tokyo/)
}

{
  const status = model.parseStatus('{"mode":"disabled","enabled":false,"backend_version":"0.2.0","protocol_version":2}')
  assert.equal(status.setupRequired, false)
  assert.equal(status.backendVersion, "0.2.0")
  assert.equal(status.protocolVersion, 2)
}

{
  const locations = [
    { id: "one", city: "Tokyo", country: "Japan", countryCode: "JP" },
    { id: "two", city: "Seattle", country: "United States", countryCode: "US" }
  ]
  assert.deepEqual(Array.from(model.filterLocations(locations, "jap"), value => value.id), ["one"])
  assert.equal(model.countryFlag(""), "--")
  assert.equal(model.countryFlag("JPN"), "JPN")
  assert.equal(Array.from(model.countryFlag("jp")).length, 2)
  assert.equal(model.statusCountryCode({ state: "connected", locations: [
    { countryCode: "FR", current: true },
    { countryCode: "JP", target: true }
  ] }), "FR")
  assert.equal(model.statusCountryCode({ state: "connecting", locations: [
    { countryCode: "FR", current: true },
    { countryCode: "JP", target: true }
  ] }), "JP")
  assert.equal(model.statusCountryCode({ state: "paused", locations: [
    { countryCode: "JP", target: true }
  ] }), "JP")
  assert.equal(model.statusCountryCode({ state: "disabled", locations: [
    { countryCode: "JP", target: true }
  ] }), "")
  assert.equal(model.isHandshakeOnlyFailure({ state: "failed", reason: "failed: handshake_fresh" }), true)
  assert.equal(model.isHandshakeOnlyFailure({ state: "failed", reason: "failed: handshake_fresh, split_dns" }), false)
  assert.equal(model.isHandshakeOnlyFailure({ state: "connected", reason: "failed: handshake_fresh" }), false)
}

{
  const invalid = model.parseStatus("not json")
  assert.equal(invalid.ok, false)
  const colors = model.parseThemeColors('green = "#00ff00"\nyellow="#ffff00"\nred = "#ff0000"')
  assert.equal(colors.green, "#00ff00")
  assert.equal(colors.yellow, "#ffff00")
  assert.equal(colors.red, "#ff0000")
}

{
  const catalog = model.parseCatalog(JSON.stringify({ ok: true, result: {
    mru: ["tokyo-fast"],
    cities: [
      { id: "United States/Seattle", profiles: [{ id: "sea" }] },
      { id: "Japan/Tokyo", profiles: [{ id: "tokyo-fast" }] }
    ]
  }}))
  assert.equal(catalog.ok, true)
  assert.deepEqual(Array.from(catalog.locations, value => value.id), ["Japan/Tokyo", "United States/Seattle"])
  assert.equal(catalog.locations[0].countryCode, "JP")

  const status = model.parseStatus(JSON.stringify({ ok: true, result: {
    mode: "paused", enabled: true, target: "Japan/Tokyo", pause_until: Date.now() / 1000 + 600,
    last_error: "stale failure must not color paused state"
  }}))
  const merged = model.mergeStatusCatalog(status, catalog)
  assert.equal(merged.paused, true)
  assert.equal(merged.locations[0].target, true)
  assert.ok(merged.countdown >= 599 && merged.countdown <= 600)
  assert.equal(merged.reason, "")
  assert.match(model.tooltip(merged), /Pause timer \(not a protection guarantee\):/)
}

{
  const catalog = model.parseCatalog(JSON.stringify({
    mru: ["recent"],
    cities: [
      { id: "Canada/Toronto", profiles: [{ id: "target" }] },
      { id: "Japan/Tokyo", profiles: [{ id: "recent" }] },
      { id: "France/Paris", profiles: [{ id: "current" }] }
    ]
  }))
  const status = model.parseStatus(JSON.stringify({
    mode: "connecting",
    enabled: true,
    target: "Canada/Toronto",
    current_profile: "current",
    last_error: "Previous attempt failed"
  }))
  const merged = model.mergeStatusCatalog(status, catalog)
  assert.deepEqual(Array.from(merged.locations, value => value.id), ["France/Paris", "Canada/Toronto", "Japan/Tokyo"])
  assert.equal(merged.location, "France/Paris")
  assert.equal(merged.reason, "Previous attempt failed")
}

{
  const locations = [
    { id: "current", city: "Tokyo", current: true, target: false },
    { id: "other", city: "Paris", current: false, target: false }
  ]
  const filtered = model.filterLocations(locations, "Paris")
  assert.equal(filtered.length, 1)
  assert.equal(model.shouldDisconnectLocation(filtered[0], "connected"), false)
  assert.equal(model.shouldDisconnectLocation(locations[0], "connected"), true)
}

{
  const catalog = model.parseCatalog(JSON.stringify({ profiles: [
    { id: "personal", label: "Personal VPN", role: "internet-exit", source_name: "home.conf" },
    { id: "work", label: "Office exit", role: "internet-exit", source_name: "office.conf", country: "Japan", city: "Tokyo" }
  ], cities: [{ id: "Ignored/City" }] }))
  assert.equal(catalog.locations.length, 2)
  assert.equal(catalog.locations[0].label, "Office exit")
  assert.equal(catalog.locations[0].role, "internet-exit")
  for (const query of ["personal", "home.conf"]) assert.equal(model.filterLocations(catalog.locations, query)[0].id, "personal")
  assert.equal(model.filterLocations(catalog.locations, "Japan")[0].id, "work")
  assert.deepEqual(Array.from(model.connectArgs(catalog.locations[0])), ["connect", "--profile", "work"])
  assert.deepEqual(Array.from(model.connectArgs({ id: "Japan/Tokyo", kind: "city" })), ["connect", "Japan/Tokyo"])
  assert.equal(model.parseCatalog('{"profiles":[],"cities":[{"id":"Old/City"}]}').locations.length, 0)
}

{
  for (const raw of ['no json', '{}', 'null', '[]', '{"ok":true}', '{"mode":"mystery"}', '{"enabled":true}']) {
    const status = model.parseStatus(raw)
    assert.equal(status.state, 'unknown', raw)
    assert.equal(status.ok, false, raw)
    assert.notEqual(status.enabled, false, raw)
  }
  assert.equal(model.parseStatus('{"mode":"connected","enabled":true}').state, 'connected')
  assert.equal(model.parseStatus('{"mode":"connected","enabled":true,"verified":false}').state, 'enabled-unverified')
  assert.equal(model.parseStatus('{"mode":"connected","enabled":false}').state, 'unknown')
  assert.equal(model.parseStatus('{"mode":"disabled","enabled":false}').state, 'disabled')
  const catalog = model.parseCatalog('{"profiles":[{"id":"a","label":"Home","role":"internet-exit"},{"id":"b","label":"Other","role":"internet-exit"}]}')
  const connected = model.mergeStatusCatalog(model.parseStatus('{"mode":"connected","enabled":true,"current_profile":"a","current":{"id":"a","label":"Home"},"target":"profile:a"}'), catalog)
  assert.equal(connected.location, 'Home')
  assert.equal(connected.locations[0].target, true)
  assert.equal(connected.locations[0].current, true)
  const unknown = model.mergeStatusCatalog(model.parseStatus('{}'), catalog)
  assert.ok(unknown.locations.every(item => !item.current && !item.target))
  assert.equal(model.shouldDisconnectLocation(connected.locations[0], 'unknown'), false)
  assert.equal(model.statusCountryCode({state:'unknown',locations:[{current:true,countryCode:'JP'}]}), '')
}

{
  assert.deepEqual(Array.from(model.importReviewArgs(['/a.zip'], {'home.conf':'Personal VPN'})), ['import','--labels','{"home.conf":"Personal VPN"}','--','/a.zip'])
  assert.deepEqual(Array.from(model.parsePickerPaths('["/a.conf","/tmp/--labels"]', false)), ['/a.conf','/tmp/--labels'])
  for (const raw of ['', '{}', '["relative.conf"]', '["/tmp/a\\n--labels"]', '["/tmp/a\\r.conf"]', '["/a",7]'])
    assert.equal(model.parsePickerPaths(raw, false), null, raw)
  assert.equal(model.parsePickerPaths('["/one","/two"]', true), null)
  assert.equal(model.validLabel('  '), false)
  assert.equal(model.validLabel('a\n'), false)
  assert.equal(model.validLabel('x'.repeat(129)), false)
  assert.equal(model.validLabel('Personal VPN'), true)
  assert.equal(model.reviewComplete(['home.conf'], {'home.conf':'Personal VPN'}), true)
  assert.equal(model.reviewComplete(['home.conf'], {}), false)
}

{
  const status = model.parseStatus('{"mode":"connected","enabled":true,"current_profile":"a","current":{"id":"a","label":"Home"},"target":"profile:b"}')
  assert.equal(model.mergeStatusCatalog(status, {locations:[]}).location,'Home')
  const catalog = model.parseCatalog('{"profiles":[{"id":"a","label":"Home","role":"internet-exit"},{"id":"b","label":"Work","role":"internet-exit"}]}')
  const merged = model.mergeStatusCatalog(status,catalog)
  assert.equal(merged.locations.filter(x=>x.current).length,1)
  assert.equal(merged.targetLabel,'Work')
}

for (const mode of ['disabled','down','offline']) {
  for (const verified of [true,false]) {
    const contradictory=model.parseStatus(JSON.stringify({mode,enabled:true,verified}))
    assert.equal(contradictory.state,'unknown')
    assert.equal(contradictory.ok,false)
    assert.equal(contradictory.enabled,null)
  }
}
console.log("model tests passed")
