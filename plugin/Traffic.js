function formatBytes(value) {
  if (value === null || value === undefined || !isFinite(value) || value < 0) return "—"
  var units = ["B", "KiB", "MiB", "GiB", "TiB", "PiB"]
  var unit = 0
  while (value >= 1024 && unit < units.length - 1) { value /= 1024; unit++ }
  return value.toFixed(unit ? 1 : 0) + " " + units[unit]
}

function summary(value) {
  if (!value) return "Traffic unavailable"
  return "↓ " + formatBytes(value.down) + "/s  ↑ " + formatBytes(value.up) + "/s"
    + "\nInterface totals: ↓ " + formatBytes(value.rx) + "  ↑ " + formatBytes(value.tx)
}

function accept(previous, raw, profile) {
  var value
  try { value = JSON.parse(raw) } catch (error) { return null }
  if (!profile || !value || value.ok !== true || value.profile !== profile
      || typeof value.uuid !== "string" || !value.uuid || !/^owg-[a-zA-Z0-9_-]+$/.test(value.interface || "")) return null
  for (var i = 0, keys = ["rx", "tx", "time", "ifindex"]; i < keys.length; i++) {
    var n = value[keys[i]]
    if (typeof n !== "number" || !isFinite(n) || n < 0 || n > 9007199254740991) return null
    if (keys[i] !== "time" && Math.floor(n) !== n) return null
  }
  if (value.time <= 0 || value.ifindex <= 0) return null
  value.down = null; value.up = null
  if (previous && previous.profile === profile) {
    var elapsed = value.time - previous.time
    if (elapsed <= 0) return null
    if (elapsed > 3 || previous.uuid !== value.uuid || previous.interface !== value.interface
        || previous.ifindex !== value.ifindex || value.rx < previous.rx || value.tx < previous.tx) return value
    value.down = (value.rx - previous.rx) / elapsed
    value.up = (value.tx - previous.tx) / elapsed
  }
  return value
}
