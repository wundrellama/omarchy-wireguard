// Proton VPN adapter model: pure parsing, validation and state helpers.
//
// proton-vpn-cli 1.0.3 has no machine-readable output, so every parser here
// accepts only the exact shapes that release prints and returns "unknown"
// otherwise. Unknown never becomes "connected". The line and table formats
// are pinned in tests/plugin/proton.test.js. Parsing ideas (ANSI stripping,
// the outdated-server-list preface, nmcli ProtonVPN naming) follow
// io.github.grichard99.omaproton-vpn (MIT); the code here is independent.

var STALE_MS = 15000
var OUTDATED = /^Server list is outdated/

function text(value) {
  return value === undefined || value === null ? "" : String(value)
}

function stripAnsi(value) {
  return text(value).replace(/\x1b\[[0-9;?]*[ -\/]*[@-~]/g, "").replace(/\r/g, "")
}

function printable(value, max) {
  var s = text(value)
  return s.length > 0 && s.length <= max && !/[\u0000-\u001f\u007f-\u009f]/.test(s)
}

function lines(raw) {
  return stripAnsi(raw).split("\n").map(function(line) { return line.replace(/\s+$/, "") })
}

// ---- argv validation -------------------------------------------------------

function validCountryCode(value) {
  return typeof value === "string" && /^[A-Z]{2}$/.test(value)
}

// Observed logical-server names: IT#23, CH-US#1, US-CA#148, JP-FREE#1,
// FR#13-TOR and US-CO#21-TOR. Nothing else is passed to the CLI.
function validServerName(value) {
  return typeof value === "string" && /^[A-Z]{2}(-[A-Z]{2,4})?#[0-9]{1,5}(-TOR)?$/.test(value)
}

// City names come from `protonvpn cities list`; accented Latin letters occur
// (Bogotá, São Paulo). Values are argv items, never shell text, but they are
// still restricted so that nothing can look like an option or a control code.
function validCity(value) {
  return typeof value === "string" && value.length >= 1 && value.length <= 64
    && /^[A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff][A-Za-z0-9\u00c0-\u024f\u1e00-\u1eff .,'()-]*$/.test(value)
    && !/\s$/.test(value)
}

var QUICK = {
  fastest: { args: [], label: "Fastest" },
  random: { args: ["--random"], label: "Random" },
  p2p: { args: ["--p2p"], label: "Fastest P2P" },
  securecore: { args: ["--securecore"], label: "Secure Core" },
  tor: { args: ["--tor"], label: "Tor" }
}

function connectArgs(choice) {
  if (!choice || typeof choice !== "object") return null
  var kind = text(choice.kind)
  if (QUICK.hasOwnProperty(kind)) return ["connect"].concat(QUICK[kind].args)
  if (kind === "country") return validCountryCode(choice.country) ? ["connect", "--country", choice.country] : null
  // The CLI ignores --country when --city is given, so only the city is sent.
  if (kind === "city") return validCity(choice.city) ? ["connect", "--city", choice.city] : null
  if (kind === "server") return validServerName(choice.server) ? ["connect", choice.server] : null
  return null
}

function choiceLabel(choice) {
  if (!choice) return ""
  if (QUICK.hasOwnProperty(text(choice.kind))) return QUICK[choice.kind].label
  if (choice.kind === "country") return text(choice.name || choice.country)
  if (choice.kind === "city") return text(choice.city)
  if (choice.kind === "server") return text(choice.server)
  return ""
}

// ---- CLI output parsers ----------------------------------------------------

// `protonvpn status`: "Status: Disconnected", or Status/Server/Load/Protocol.
function parseStatus(raw) {
  var unknown = { ok: false, state: "unknown", server: "", location: "", load: "", protocol: "" }
  var fields = {}
  var rows = lines(raw)
  for (var i = 0; i < rows.length; i++) {
    var line = rows[i].trim()
    if (!line || OUTDATED.test(line)) continue
    var match = line.match(/^(Status|Server|Load|Protocol): ?(.*)$/)
    if (!match) continue
    if (fields.hasOwnProperty(match[1])) return unknown
    fields[match[1]] = match[2].trim()
  }
  if (fields.Status === "Disconnected")
    return { ok: true, state: "disconnected", server: "", location: "", load: "", protocol: "" }
  if (fields.Status !== "Connected") return unknown
  var server = text(fields.Server).match(/^(\S+) in (.+)$/)
  if (!server || !validServerName(server[1]) || !printable(server[2], 100)) return unknown
  if (!/^[0-9]{1,3}%$/.test(text(fields.Load)) || !/^[a-z0-9-]{1,32}$/.test(text(fields.Protocol))) return unknown
  return { ok: true, state: "connected", server: server[1], location: server[2], load: fields.Load, protocol: fields.Protocol }
}

// `protonvpn countries list`: "Country  Code" table, rows "Name<spaces>CC".
function parseCountries(raw) {
  var result = []
  var seen = {}
  var rows = lines(raw)
  for (var i = 0; i < rows.length; i++) {
    var match = rows[i].match(/^(\S.*?)\s{2,}([A-Z]{2})$/)
    if (!match || match[1] === "Country" || !printable(match[1], 64) || seen[match[2]]) continue
    seen[match[2]] = true
    result.push({ name: match[1], code: match[2] })
  }
  return result
}

// `protonvpn cities list CC`: "Cities in X:" then a "City  Features" table.
function parseCities(raw) {
  var result = []
  var rows = lines(raw)
  var state = 0
  for (var i = 0; i < rows.length; i++) {
    var line = rows[i]
    if (state === 0) { if (/^City\s{2,}Features$/.test(line)) state = 1; continue }
    if (state === 1) { state = /^-+\s+-+$/.test(line) ? 2 : 0; continue }
    if (!line) break
    var match = line.match(/^(\S.*?)(?:\s{2,}(.*))?$/)
    if (!match || !validCity(match[1])) continue
    var features = text(match[2]).split(",").map(function(item) { return item.trim() })
      .filter(function(item) { return /^[A-Za-z0-9 -]{1,20}$/.test(item) })
    result.push({ name: match[1], features: features })
  }
  return result
}

// `protonvpn info` prints "Account: '<name>'" or "Account: 'None'". Only the
// signed-in state is kept; the account name never leaves this function.
function parseAccount(raw) {
  var rows = lines(raw)
  for (var i = 0; i < rows.length; i++) {
    var match = rows[i].trim().match(/^Account: '(.*)'$/)
    if (!match) continue
    if (match[1] === "None") return "signed-out"
    return match[1] ? "signed-in" : "unknown"
  }
  return "unknown"
}

function accountFromError(raw) {
  return /authentication required|not signed in|not logged in/i.test(stripAnsi(raw)) ? "signed-out" : "unknown"
}

// `protonvpn config list`: exactly one "kill-switch  <value>" row.
function parseKillSwitch(raw) {
  var found = []
  var rows = lines(raw)
  for (var i = 0; i < rows.length; i++) {
    var match = rows[i].match(/^kill-switch\s{2,}([a-z-]{1,20})$/)
    if (match) found.push(match[1])
  }
  return found.length === 1 ? found[0] : ""
}

// The CLI prints click errors as "Error: <message>". Show the message only.
function errorMessage(raw, fallback) {
  var rows = lines(raw).map(function(line) { return line.replace(/[\u0000-\u001f\u007f-\u009f]/g, "").trim() })
    .filter(function(line) { return line !== "" })
  var message = ""
  for (var i = rows.length - 1; i >= 0 && !message; i--) {
    var match = rows[i].match(/^Error:\s*(.+)$/)
    if (match) message = match[1]
  }
  for (var j = rows.length - 1; j >= 0 && !message; j--) {
    if (!OUTDATED.test(rows[j]) && !/^Usage:/.test(rows[j]) && !/^Try '/.test(rows[j])) message = rows[j]
  }
  message = message || text(fallback)
  return message.length > 300 ? message.substring(0, 297) + "..." : message
}

// nmcli -t escapes ":" and "\" inside fields.
function splitTerse(line) {
  var fields = [""]
  for (var i = 0; i < line.length; i++) {
    var c = line.charAt(i)
    if (c === "\\" && i + 1 < line.length) { fields[fields.length - 1] += line.charAt(++i); continue }
    if (c === ":") fields.push("")
    else fields[fields.length - 1] += c
  }
  return fields
}

// `nmcli -t -f NAME,UUID,TYPE,DEVICE,STATE connection show --active`.
// Exactly one "ProtonVPN <server>" wireguard connection on proton0 is a
// Proton tunnel. Any other connection using that name prefix or that device
// makes the observation ambiguous (unknown), never a fallback match.
function parseActive(raw) {
  var candidates = []
  var rows = lines(raw)
  for (var i = 0; i < rows.length; i++) {
    if (!rows[i]) continue
    var fields = splitTerse(rows[i])
    if (fields.length !== 5) {
      // A malformed row mentioning Proton is ambiguous, never skipped.
      if (rows[i].indexOf("ProtonVPN ") !== -1 || rows[i].indexOf("proton0") !== -1)
        return { ok: true, match: "ambiguous", server: "", activated: false }
      continue
    }
    if (fields[0].indexOf("ProtonVPN ") !== 0 && fields[3] !== "proton0") continue
    candidates.push(fields)
  }
  if (candidates.length === 0) return { ok: true, match: "none", server: "", activated: false }
  var row = candidates[0]
  if (candidates.length !== 1 || row[0].indexOf("ProtonVPN ") !== 0 || row[2] !== "wireguard" || row[3] !== "proton0")
    return { ok: true, match: "ambiguous", server: "", activated: false }
  var server = row[0].substring(10)
  return { ok: true, match: "one", server: validServerName(server) ? server : "", activated: row[4] === "activated" }
}

// `proton_servers.py` output: {ok, fields, servers: [[name, country, city,
// features, load, tier], ...]}. Every row is checked again here; a row that
// fails any check is dropped, so only valid names can reach connectArgs.
var FEATURE_WORDS = { securecore: true, tor: true, p2p: true, streaming: true, ipv6: true }

function parseServerIndex(raw) {
  var parsed
  try { parsed = JSON.parse(text(raw)) } catch (error) { return { ok: false, servers: [] } }
  if (!parsed || parsed.ok !== true || !Array.isArray(parsed.servers)) return { ok: false, servers: [] }
  var servers = []
  for (var i = 0; i < parsed.servers.length && servers.length < 30000; i++) {
    var row = parsed.servers[i]
    if (!Array.isArray(row) || row.length !== 6 || !validServerName(row[0]) || !validCountryCode(row[1])) continue
    if (!Array.isArray(row[3]) || !row[3].every(function(word) { return FEATURE_WORDS.hasOwnProperty(word) })) continue
    if (typeof row[4] !== "number" || row[4] < 0 || row[4] > 100 || typeof row[5] !== "number") continue
    servers.push({ name: row[0], country: row[1], city: validCity(row[2]) ? row[2] : "", features: row[3].slice(), load: row[4], tier: row[5] })
  }
  return { ok: true, servers: servers }
}

// One live search over countries (name or code), cities (from the server
// index and loaded `cities list` output) and servers (name, city or feature
// word). An empty query lists the countries. Other queries return at most
// `limit` results (default 30): countries, then cities, then servers with
// the exact name first and the lowest load next.
function searchProton(query, countries, cities, servers, limit) {
  var needle = text(query).trim().toLowerCase()
  var max = limit > 0 ? limit : 30
  var countryList = (Array.isArray(countries) ? countries : []).filter(function(item) {
    return item && validCountryCode(item.code) && printable(item.name, 64)
  })
  var names = {}
  countryList.forEach(function(item) { names[item.code] = item.name })
  var countryResult = function(item) {
    return { kind: "country", code: item.code, name: item.name, label: item.name + " (" + item.code + ")",
      choice: { kind: "country", country: item.code, name: item.name } }
  }
  if (!needle) return countryList.map(countryResult)
  var results = countryList.filter(function(item) {
    return item.name.toLowerCase().indexOf(needle) !== -1 || item.code.toLowerCase() === needle
  }).map(countryResult)
  var serverList = Array.isArray(servers) ? servers : []
  var seen = {}
  var addCity = function(code, city) {
    if (!validCountryCode(code) || !validCity(city) || city.toLowerCase().indexOf(needle) === -1 || seen[code + "\n" + city]) return
    seen[code + "\n" + city] = true
    results.push({ kind: "city", city: city, country: code, label: city, detail: names[code] || code,
      choice: { kind: "city", country: code, city: city } })
  }
  var cityMap = cities && typeof cities === "object" ? cities : {}
  for (var code in cityMap) (Array.isArray(cityMap[code]) ? cityMap[code] : []).forEach(function(item) { addCity(code, item && item.name) })
  serverList.forEach(function(item) { addCity(item.country, item.city) })
  var upper = needle.toUpperCase()
  var matches = serverList.filter(function(item) {
    return validServerName(item.name) && (item.name.toLowerCase().indexOf(needle) !== -1
      || (item.city && item.city.toLowerCase().indexOf(needle) !== -1)
      || (Array.isArray(item.features) && item.features.indexOf(needle) !== -1))
  })
  var rank = function(item) { return item.name === upper ? 0 : (item.name.indexOf(upper) === 0 ? 1 : 2) }
  matches.sort(function(a, b) { return rank(a) - rank(b) || a.load - b.load || a.name.localeCompare(b.name) })
  for (var i = 0; i < matches.length && results.length < max; i++) {
    var server = matches[i]
    results.push({ kind: "server", server: server.name, country: server.country, label: server.name,
      detail: [server.city, names[server.country] || server.country, "Load " + server.load + "%"].concat(server.features)
        .filter(function(v) { return !!v }).join(" · "),
      choice: { kind: "server", server: server.name } })
  }
  return results.slice(0, max)
}

// ---- last connection and the quick connect button ---------------------------
// A record is only a choice descriptor: {version: 1, kind, value, label}.
// kind is "wireguard" (value = catalog location ID), a QUICK key (value ""),
// "server", "country" or "city". It never holds account data.

function lastFromLocation(location) {
  if (!location || !printable(location.id, 128)) return null
  var label = text(location.label || location.city || location.id)
  return { version: 1, kind: "wireguard", value: text(location.id), label: printable(label, 128) ? label : text(location.id) }
}

function lastFromChoice(choice) {
  if (!connectArgs(choice)) return null
  var kind = choice.kind
  var value = kind === "server" ? choice.server : kind === "country" ? choice.country : kind === "city" ? choice.city : ""
  var label = choiceLabel(choice)
  return { version: 1, kind: kind, value: value, label: printable(label, 128) ? label : value }
}

function validLast(record) {
  if (!record || typeof record !== "object" || Array.isArray(record) || record.version !== 1) return false
  var keys = Object.keys(record).sort().join(",")
  if (keys !== "kind,label,value,version" || !printable(record.label, 128) || typeof record.value !== "string") return false
  if (record.kind === "wireguard") return printable(record.value, 128)
  if (QUICK.hasOwnProperty(record.kind)) return record.value === ""
  return !!connectArgs(lastChoice(record))
}

function lastChoice(record) {
  if (QUICK.hasOwnProperty(record.kind)) return { kind: record.kind }
  if (record.kind === "server") return { kind: "server", server: record.value }
  if (record.kind === "country") return { kind: "country", country: record.value, name: record.label }
  if (record.kind === "city") return { kind: "city", city: record.value }
  return null
}

// Output of `last_connection.py read`. Anything unexpected gives null.
function parseLastConnection(raw) {
  var parsed
  try { parsed = JSON.parse(text(raw)) } catch (error) { return null }
  if (!parsed || parsed.ok !== true || !validLast(parsed.connection)) return null
  return parsed.connection
}

function findLocation(locations, match) {
  var list = Array.isArray(locations) ? locations : []
  for (var i = 0; i < list.length; i++) if (list[i] && match(list[i])) return list[i]
  return null
}

// The one quick button. Input: {wg, recovery, wgAbsent, proton, switching,
// busy, protonBusy, record, locations, mru, countries}. protonBusy is true
// while a Proton command (connect, disconnect, config read) is running. Output: {mode, label, vpn,
// enabled, target}. mode is "connect", "disconnect", "disabled" or "hidden".
// Unknown or conflicting status never connects and never guesses.
function quickAction(input) {
  var s = input || {}
  var wg = s.wg || {}
  var proton = s.proton || null
  var off = function(label) { return { mode: "disabled", label: label, vpn: "", enabled: false, target: null } }
  var protonKnown = !!proton && proton.installed !== false && proton.state !== "absent" && !!proton.state
  var pState = protonKnown ? text(proton.state) : ""
  if (s.switching || (proton && proton.phase)) return off("Switching VPN")
  var busy = s.busy === true || s.protonBusy === true
  var wgUnknown = text(wg.state || "unknown") === "unknown" && s.wgAbsent !== true
  var wgActive = wireGuardActive(wg, s.recovery) || wg.state === "paused"
  var pActive = pState === "connected" || pState === "connecting" || pState === "disconnecting"
  if (wgActive && pActive) return off("Conflict: both VPNs are active")
  if (wgUnknown || (protonKnown && pState === "unknown")) return off("VPN status unknown")
  if (wgActive) return { mode: "disconnect", vpn: "wireguard", enabled: !busy, target: null,
    label: "Disconnect " + text(wg.location || wg.targetLabel || "WireGuard") }
  if (pActive) return { mode: "disconnect", vpn: "proton", enabled: !busy && pState !== "disconnecting", target: null,
    label: "Disconnect Proton VPN" }
  var wgReady = wg.state === "disabled" && s.wgAbsent !== true
  var protonReady = protonKnown && proton.installed === true && pState === "disconnected" && proton.account !== "signed-out"
  var connect = function(vpn, label, target) { return { mode: "connect", vpn: vpn, label: "Connect: " + label, enabled: !busy, target: target } }
  var record = validLast(s.record) ? s.record : null
  if (record && record.kind === "wireguard" && wgReady) {
    var saved = findLocation(s.locations, function(item) { return item.id === record.value })
    if (saved) return connect("wireguard", text(saved.label || saved.city || saved.id), { location: saved })
  } else if (record && record.kind !== "wireguard" && protonReady) {
    var choice = lastChoice(record)
    var label = choiceLabel(choice)
    if (record.kind === "country") {
      var country = findLocation(s.countries, function(item) { return item.code === record.value })
      label = country ? text(country.name) : record.label
      choice.name = label
    }
    return connect("proton", "Proton " + label, { choice: choice })
  }
  var mru = Array.isArray(s.mru) ? s.mru : []
  for (var i = 0; wgReady && i < mru.length; i++) {
    var recent = findLocation(s.locations, function(item) {
      return item.id === mru[i] || (Array.isArray(item.profileIds) && item.profileIds.indexOf(mru[i]) !== -1)
    })
    if (recent) return connect("wireguard", text(recent.label || recent.city || recent.id), { location: recent })
  }
  if (protonReady && proton.account === "signed-in") return connect("proton", "Proton Fastest", { choice: { kind: "fastest" } })
  return { mode: "hidden", label: "", vpn: "", enabled: false, target: null }
}

function filterCountries(countries, query) {
  var needle = text(query).trim().toLowerCase()
  var source = Array.isArray(countries) ? countries : []
  if (!needle) return source.slice()
  return source.filter(function(item) {
    return text(item.name).toLowerCase().indexOf(needle) !== -1 || text(item.code).toLowerCase() === needle
  })
}

// ---- state -----------------------------------------------------------------

function fresh(observation, now) {
  return !!observation && observation.ok === true && Number(observation.at) > 0 && now - observation.at <= STALE_MS
}

// nmcli is the authority for "a Proton tunnel exists"; the slower CLI status
// only adds details, and a newer CLI "connected" that nmcli does not show is
// a contradiction (unknown).
function deriveState(input) {
  var s = input || {}
  if (s.installed === false) return "absent"
  if (s.action === "connect") return "connecting"
  if (s.action === "disconnect") return "disconnecting"
  var nm = s.nm || {}
  if (!fresh(nm, s.now)) return "unknown"
  if (nm.match === "one") return nm.activated ? "connected" : "connecting"
  if (nm.match !== "none") return "unknown"
  var cli = s.cli || {}
  if (fresh(cli, s.now) && cli.state === "connected" && cli.at > nm.at) return "unknown"
  return "disconnected"
}

function buildStatus(input) {
  var s = input || {}
  var state = deriveState(s)
  var nm = s.nm || {}
  var cli = s.cli || {}
  var details = state === "connected" && fresh(cli, s.now) && cli.state === "connected" && cli.server === nm.server
  return {
    installed: s.installed,
    state: state,
    phase: text(s.phase),
    error: text(s.error),
    message: text(s.message),
    account: text(s.account) || "unknown",
    server: state === "connected" || state === "connecting" ? text(nm.server) : "",
    location: details ? cli.location : "",
    load: details ? cli.load : "",
    protocol: details ? cli.protocol : ""
  }
}

function wireGuardActive(status, recovery) {
  var value = status || {}
  var state = text(value.state)
  return value.enabled === true || state === "connected" || state === "connecting" || state === "failed"
    || state === "enabled-unverified" || (state === "unknown" && recovery === true)
}

// Proton may start only after a WireGuard status poll newer than the
// disconnect reports the backend disabled (its firewall is then removed).
function wireGuardReleased(status, observedAt, disconnectedAt) {
  var value = status || {}
  return value.state === "disabled" && value.enabled === false && Number(observedAt) > Number(disconnectedAt)
}

// `absent` is true only when the WireGuard backend is known not installed.
// Proton renders green only against a known-disabled or known-absent
// WireGuard; unknown WireGuard state keeps the shield muted, never green.
function shield(wg, proton, recovery, absent) {
  var value = wg || {}
  var wgState = text(value.state) || "unknown"
  var wgNamed = wgState !== "disabled" && wgState !== "unknown"
  var wgResult = { state: wgState, vpn: wgNamed ? "WireGuard" : "", label: "WireGuard " + wgState }
  if (!proton || proton.state === "absent" || !proton.state) return wgResult
  if (proton.phase) return { state: "connecting", vpn: "", label: "Switching VPN" }
  var pState = proton.state
  var pActive = pState === "connected" || pState === "connecting" || pState === "disconnecting"
  var wgActive = wireGuardActive(value, recovery)
  if (pActive && wgActive) return { state: "conflict", vpn: "", label: "Conflict: WireGuard and Proton VPN both report active" }
  if (pState === "connected" && wgState === "unknown" && absent !== true)
    return { state: "unknown", vpn: "", label: "WireGuard status unknown; Proton VPN connected" }
  if (pState === "connected") return { state: "connected", vpn: "Proton", label: "Proton VPN connected" }
  if (pActive) return { state: "connecting", vpn: "Proton", label: "Proton VPN " + pState }
  if (wgActive || wgNamed) return wgResult
  if (proton.error) return { state: "failed", vpn: "Proton", label: "Proton VPN error" }
  if (pState === "unknown") return { state: "unknown", vpn: "", label: "Proton VPN status unknown" }
  return wgResult
}

function tooltip(result, wg, proton) {
  if (!proton || proton.state === "absent" || !proton.state) return ""
  var out = []
  if (result && result.state === "conflict") out.push("Conflict: WireGuard and Proton VPN both report active; protection is unclear")
  else if (result && result.vpn) out.push("Active VPN: " + (result.vpn === "Proton" ? "Proton VPN" : result.vpn))
  if (proton.phase) out.push("Switching VPN: traffic can use the regular connection")
  out.push("Proton VPN: " + proton.state)
  if (proton.server) out.push("Proton server: " + proton.server + (proton.location ? " (" + proton.location + ")" : ""))
  if (proton.load || proton.protocol) out.push([proton.load ? "Load " + proton.load : "", proton.protocol].filter(function(v) { return !!v }).join(" · "))
  if (proton.error) out.push("Proton error: " + proton.error)
  return out.join("\n")
}

function summary(status) {
  if (!status || !status.state) return ""
  if (status.installed === false) return "Proton VPN CLI (protonvpn) is not installed"
  if (status.installed !== true) return "Checking for the Proton VPN CLI"
  if (status.account === "signed-out" && status.state !== "connected") return "Signed out. Sign in with Proton's own client; this panel never handles your password."
  if (status.state === "connected")
    return ["Connected", status.server, status.location, status.load ? "Load " + status.load : "", status.protocol]
      .filter(function(v) { return !!v }).join(" · ")
  if (status.state === "connecting") return "Connecting" + (status.server ? " · " + status.server : "")
  if (status.state === "disconnecting") return "Disconnecting"
  if (status.state === "disconnected") return "Disconnected" + (status.account === "signed-in" ? " · signed in" : "")
  return "Status unknown; not treated as protected"
}

// Traffic sampler key: a WireGuard profile ID, or "@proton" (which cannot be
// a profile ID) for the exact Proton mapping mode of traffic.py.
function trafficProfile(wg, result) {
  if (!result || result.state !== "connected") return ""
  if (result.vpn === "Proton") return "@proton"
  var value = wg || {}
  return result.vpn === "WireGuard" && value.state === "connected" ? text(value.currentProfile) : ""
}
