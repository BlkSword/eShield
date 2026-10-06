// Renders design/console-v2/preview.html with an installed Chrome/Edge and
// writes PNG previews. Usage: node scripts/shot.mjs [chromePath]
import { chromium } from 'playwright-core'
import { fileURLToPath } from 'node:url'
import { dirname, resolve } from 'node:path'

const here = dirname(fileURLToPath(import.meta.url))
const root = resolve(here, '../../')           // repo root
const out = resolve(root, 'design/console-v2')
const preview = resolve(out, 'preview.html')
const exe = process.argv[2] || 'C:/Program Files/Google/Chrome/Application/chrome.exe'
const pages = [
  ['overview', '#/overview'], ['attacks', '#/attacks'], ['modules', '#/modules'],
  ['access', '#/access'], ['l7', '#/l7'], ['projects', '#/projects'],
  ['geoip', '#/geoip'], ['rules', '#/rules'], ['settings', '#/settings'], ['login', '#/login'],
]
const browser = await chromium.launch({ executablePath: exe, headless: true })
const page = await browser.newPage({ viewport: { width: 1600, height: 1000 }, deviceScaleFactor: 1.4 })
const errors = []
page.on('pageerror', (e) => errors.push(String(e)))
page.on('console', (m) => { if (m.type() === 'error') errors.push(m.text()) })
for (const [name, hash] of pages) {
  const url = 'file:///' + preview.split(String.fromCharCode(92)).join('/') + hash
  await page.goto(url, { waitUntil: 'load' })
  await page.waitForTimeout(1500)
  await page.screenshot({ path: `${out}/${name}.png` })
  if (name === 'overview') await page.screenshot({ path: `${out}/overview-full.png`, fullPage: true })
  console.log('shot', name)
}
console.log('errors:', JSON.stringify(errors.slice(0, 12), null, 2))
await browser.close()
