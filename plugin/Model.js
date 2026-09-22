function object(value) {
  return value && typeof value === "object" && !Array.isArray(value) ? value : {}
}

function first(value, keys, fallback) {
  var source = object(value)
  for (var i = 0; i < keys.length; i++) {
    var candidate = source[keys[i]]
    if (candidate !== undefined && candidate !== null) return candidate
  }
  return fallback
}

function text(value) {
  return value === undefined || value === null ? "" : String(value)
}

function normalizeState(value, enabled, verified, paused) {
  var state = text(value).trim().toLowerCase().replace(/[ _]+/g, "-")
  if (paused || state === "pause" || state === "paused") return "paused"
  if (state === "up" || state === "online" || state === "connected") return "connected"
  if (state === "connecting" || state === "disconnecting" || state === "retrying") return "connecting"
  if (state === "failed" || state === "failure" || state === "error") return "failed"
  if (state === "enabled-unverified" || (enabled && verified === false)) return "enabled-unverified"
  if (state === "disabled" || state === "down" || state === "offline" || !enabled) return "disabled"
  return state || "disabled"
}

function normalizeLocation(value) {
  var item = object(value)
  var city = text(first(item, ["city", "name", "label"], "Unknown location"))
  var country = text(first(item, ["country", "country_name", "countryName"], ""))
  return {
    id: text(first(item, ["id", "slug", "profile", "key"], city)),
    city: city,
    country: country,
    countryCode: text(first(item, ["country_code", "countryCode", "code"], "")).toUpperCase(),
    current: first(item, ["current", "active", "connected"], false) === true,
    target: first(item, ["target", "pending", "connecting"], false) === true,
    failed: first(item, ["failed", "error"], false) === true,
    detail: text(first(item, ["detail", "status", "endpoint"], ""))
  }
}

function parseStatus(raw) {
  var parsed
  try {
    parsed = JSON.parse(text(raw))
  } catch (error) {
    return { ok: false, message: "Invalid backend response", reason: text(error.message) }
  }
  parsed = object(parsed)
  if (parsed.ok === false) {
    var responseError = object(parsed.error)
    return { ok: false, message: text(responseError.message || "Backend request failed"), reason: text(responseError.code) }
  }
  if (parsed.result !== undefined) parsed = object(parsed.result)
  var setup = object(first(parsed, ["setup", "first_run", "firstRun"], {}))
  var enabled = first(parsed, ["enabled", "vpn_enabled", "vpnEnabled"], true) !== false
  var verified = first(parsed, ["verified", "connection_verified", "connectionVerified"], true) !== false
  var paused = first(parsed, ["paused", "is_paused", "isPaused"], false) === true
  var locationsRaw = first(parsed, ["locations", "servers", "profiles"], [])
  if (!Array.isArray(locationsRaw)) locationsRaw = []
  var locations = []
  for (var i = 0; i < locationsRaw.length; i++) locations.push(normalizeLocation(locationsRaw[i]))
  var currentId = text(first(parsed, ["current_location_id", "currentLocationId", "current_profile", "current"], ""))
  var targetId = text(first(parsed, ["target_location_id", "targetLocationId", "target"], ""))
  for (var j = 0; j < locations.length; j++) {
    if (currentId && locations[j].id === currentId) locations[j].current = true
    if (targetId && locations[j].id === targetId) locations[j].target = true
  }
  var errors = first(parsed, ["errors", "problems"], [])
  if (!Array.isArray(errors)) errors = errors ? [errors] : []
  var normalizedErrors = []
  for (var k = 0; k < errors.length; k++) normalizedErrors.push(text(first(errors[k], ["message", "reason"], errors[k])))
  var review = object(first(parsed, ["import_review", "importReview", "review"], {}))
  var normalizedState = normalizeState(first(parsed, ["mode", "state", "status"], ""), enabled, verified, paused)
  var lastError = text(first(parsed, ["reason", "message", "last_error", "lastError"], ""))
  return {
    ok: true,
    installed: first(parsed, ["installed", "backend_installed", "backendInstalled"], true) !== false,
    setupRequired: first(parsed, ["setup_required", "setupRequired"], false) === true || setup.required === true,
    enabled: enabled,
    verified: verified,
    paused: paused || normalizedState === "paused",
    state: normalizedState,
    currentProfile: currentId,
    location: text(first(parsed, ["location", "current_location", "currentLocation"], "")),
    targetLocation: text(first(parsed, ["target_location", "targetLocation", "target"], "")),
    reason: normalizedState === "failed" || normalizedState === "connecting" || normalizedState === "enabled-unverified" ? lastError : "",
    countdown: countdownFromStatus(parsed),
    backendNotifies: first(parsed, ["notifications", "backend_notifications", "backendNotifies"], false) === true,
    locations: orderedLocations(locations),
    errors: normalizedErrors,
    setup: setup,
    importReview: {
      ambiguous: review.ambiguous === true,
      message: text(first(review, ["message", "reason"], "")),
      candidates: Array.isArray(review.candidates) ? review.candidates : []
    }
  }
}

function countdownFromStatus(status) {
  var direct = Number(first(status, ["countdown_seconds", "countdown", "retry_in", "retryIn"], 0)) || 0
  if (direct > 0) return direct
  var deadline = Number(first(status, ["pause_until", "retry_at"], 0)) || 0
  return deadline > 0 ? Math.max(0, Math.ceil(deadline - Date.now() / 1000)) : 0
}

function countryCode(country) {
  var codes = {
    "Australia": "AU", "Austria": "AT", "Belgium": "BE", "Brazil": "BR",
    "Canada": "CA", "Switzerland": "CH", "Germany": "DE", "Denmark": "DK",
    "Spain": "ES", "Finland": "FI", "France": "FR", "United Kingdom": "GB",
    "Hong Kong": "HK", "Ireland": "IE", "India": "IN", "Italy": "IT",
    "Japan": "JP", "Mexico": "MX", "Netherlands": "NL", "Norway": "NO",
    "New Zealand": "NZ", "Poland": "PL", "Portugal": "PT", "Romania": "RO",
    "Sweden": "SE", "Singapore": "SG", "United States": "US"
  }
  return codes[text(country)] || ""
}

function parseCatalog(raw) {
  var parsed
  try {
    parsed = JSON.parse(text(raw))
  } catch (error) {
    return { ok: false, message: "Invalid location response", locations: [] }
  }
  parsed = object(parsed)
  if (parsed.ok === false) return { ok: false, message: text(object(parsed.error).message || "Could not list locations"), locations: [] }
  if (parsed.result !== undefined) parsed = object(parsed.result)
  var cities = Array.isArray(parsed.cities) ? parsed.cities : []
  var mru = Array.isArray(parsed.mru) ? parsed.mru : []
  var mruOrder = {}
  for (var m = 0; m < mru.length; m++) mruOrder[text(mru[m])] = m
  var locations = []
  for (var i = 0; i < cities.length; i++) {
    var city = object(cities[i])
    var id = text(city.id)
    var slash = id.indexOf("/")
    var country = slash >= 0 ? id.substring(0, slash) : ""
    var cityName = slash >= 0 ? id.substring(slash + 1) : id
    var rank = 1000000
    var profiles = Array.isArray(city.profiles) ? city.profiles : []
    for (var p = 0; p < profiles.length; p++) {
      var profileRank = mruOrder[text(object(profiles[p]).id)]
      if (profileRank !== undefined) rank = Math.min(rank, profileRank)
    }
    var profileIds = []
    for (var q = 0; q < profiles.length; q++) profileIds.push(text(object(profiles[q]).id))
    locations.push({ id: id, city: cityName, country: country, countryCode: countryCode(country), current: false, target: false, failed: false, detail: "", mruRank: rank, profileIds: profileIds })
  }
  locations.sort(function(a, b) {
    if (a.mruRank !== b.mruRank) return a.mruRank - b.mruRank
    return (a.country + "\n" + a.city).localeCompare(b.country + "\n" + b.city)
  })
  return { ok: true, locations: locations }
}

function mergeStatusCatalog(status, catalog) {
  var next = {}
  var source = object(status)
  for (var key in source) next[key] = source[key]
  var locations = []
  var sourceLocations = catalog && Array.isArray(catalog.locations) ? catalog.locations : []
  for (var i = 0; i < sourceLocations.length; i++) {
    var item = {}
    for (var field in sourceLocations[i]) item[field] = sourceLocations[i][field]
    item.target = item.id === source.targetLocation
    item.current = text(source.currentProfile) !== "" && Array.isArray(item.profileIds) && item.profileIds.indexOf(text(source.currentProfile)) !== -1
    if (!item.current && item.target && source.state === "connected") item.current = true
    item.failed = item.target && source.state === "failed"
    locations.push(item)
  }
  next.locations = orderedLocations(locations)
  next.location = ""
  for (var j = 0; j < next.locations.length; j++) {
    if (next.locations[j].current) { next.location = next.locations[j].id; break }
  }
  next.setupRequired = next.setupRequired === true || locations.length === 0
  return next
}

function orderedLocations(locations) {
  var source = Array.isArray(locations) ? locations : []
  var result = []
  var seen = {}
  for (var pass = 0; pass < 3; pass++) {
    for (var i = 0; i < source.length; i++) {
      var item = source[i]
      if (!item) continue
      var key = text(item.id) || (text(item.city) + "\n" + text(item.country))
      var selected = pass === 0 ? item.current === true : (pass === 1 ? item.target === true : true)
      if (!selected || seen[key]) continue
      seen[key] = true
      result.push(item)
    }
  }
  return result
}

function filterLocations(locations, query) {
  var needle = text(query).trim().toLowerCase()
  if (!needle) return Array.isArray(locations) ? locations.slice() : []
  return (Array.isArray(locations) ? locations : []).filter(function(item) {
    return (text(item.city) + " " + text(item.country) + " " + text(item.countryCode)).toLowerCase().indexOf(needle) !== -1
  })
}

function shouldDisconnectLocation(location, state) {
  var item = object(location)
  var mode = text(state)
  return (item.current === true || item.target === true)
    && (mode === "connected" || mode === "failed" || mode === "enabled-unverified")
}

function countryFlag(code) {
  var value = text(code).trim().toUpperCase()
  if (!/^[A-Z]{2}$/.test(value)) return value || "--"
  return String.fromCodePoint(0x1f1e6 + value.charCodeAt(0) - 65, 0x1f1e6 + value.charCodeAt(1) - 65)
}

function statusCountryCode(status) {
  var value = object(status)
  if (text(value.state) === "disabled") return ""
  var locations = Array.isArray(value.locations) ? value.locations : []
  var preferCurrent = text(value.state) === "connected"
  for (var pass = 0; pass < 2; pass++) {
    for (var i = 0; i < locations.length; i++) {
      var selected = preferCurrent ? locations[i].current === true : locations[i].target === true
      var code = text(locations[i].countryCode).toUpperCase()
      if (selected && code) return code
    }
    preferCurrent = !preferCurrent
  }
  return ""
}

function isHandshakeOnlyFailure(status) {
  var value = object(status)
  return text(value.state) === "failed"
    && text(value.reason).trim().toLowerCase() === "failed: handshake_fresh"
}

function countdownText(seconds) {
  var total = Math.max(0, Math.floor(Number(seconds) || 0))
  if (!total) return ""
  var minutes = Math.floor(total / 60)
  var remainder = total % 60
  return (minutes ? minutes + "m " : "") + remainder + "s"
}

function tooltip(status) {
  var value = object(status)
  var lines = ["WireGuard: " + (text(value.state) || "checking")]
  var location = text(value.targetLocation) || text(value.location)
  if (location) lines.push("Location: " + location)
  if (value.reason) lines.push("Reason: " + text(value.reason))
  var countdown = countdownText(value.countdown)
  if (countdown) lines.push((value.state === "paused" ? "Resumes in: " : "Retry in: ") + countdown)
  return lines.join("\n")
}

function parseThemeColors(raw) {
  var result = {}
  var lines = text(raw).split("\n")
  for (var i = 0; i < lines.length; i++) {
    var match = lines[i].match(/^\s*(green|yellow|red|muted)\s*=\s*["']?(#[0-9a-fA-F]{6})/)
    if (match) result[match[1]] = match[2]
  }
  return result
}
