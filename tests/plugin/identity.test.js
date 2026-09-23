const assert = require('node:assert/strict')
const fs = require('node:fs')
const path = require('node:path')
const root = path.join(__dirname, '../..')
const manifest = JSON.parse(fs.readFileSync(path.join(root, 'manifest.json'), 'utf8'))
assert.equal(manifest.id, 'wundrellama.wireguard')
assert.equal(manifest.author, 'wundrellama')
for (const file of ['plugin/BarWidget.qml', 'scripts/integrate-user', 'scripts/uninstall-backend']) {
  const text = fs.readFileSync(path.join(root, file), 'utf8')
  assert.ok(text.includes('wundrellama.wireguard'), file)
  assert.ok(!text.includes('nicolasdorier.wireguard'), file)
}
assert.match(fs.readFileSync(path.join(root, 'LICENSE'), 'utf8'), /Copyright.*Nicolas Dorier/)
console.log('plugin identity and upstream attribution passed')
