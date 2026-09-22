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
  assert.deepEqual(Array.from(status.locations, value => value.id), ["tyo", "lon", "la"])
  assert.equal(model.countdownText(status.countdown), "1m 5s")
  assert.match(model.tooltip(status), /Location: Tokyo/)
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
  assert.match(model.tooltip(merged), /Resumes in:/)
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

console.log("model tests passed")
