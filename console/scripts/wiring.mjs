// End-to-end wiring check: drives the built console against scripts/mockapi.py
// (which returns the same JSON envelopes as the Rust backend) and asserts that
// every page renders live data instead of falling back to mock data.
import { chromium } from 'playwright-core'

const exe = process.argv[2] || 'C:/Program Files/Google/Chrome/Application/chrome.exe'
const base = process.argv[3] || 'http://127.0.0.1:8898'
const browser = await chromium.launch({ executablePath: exe, headless: true })
const page = await browser.newPage({ viewport: { width: 1500, height: 950 } })
const pageErrors = []
page.on('pageerror', (e) => pageErrors.push(String(e)))

const results = {}
async function check(name, hash, musts) {
  await page.goto(base + '/#' + hash, { waitUntil: 'load' })
  await page.waitForTimeout(1400)
  const text = await page.evaluate(() => document.body.innerText)
  const missing = musts.filter((m) => !text.includes(m))
  const live = text.includes('实时')
  results[name] = { live, missing, ok: missing.length === 0 }
}
await page.goto(base + '/#/overview', { waitUntil: 'load' })
await page.waitForTimeout(1600)
await check('overview', '/overview', ['3.28B', '1.48M', '实时'])
await check('attacks', '/attacks', ['203.0.113.9', '黑名单'])
await check('packets', '/packets', ['47 45 54'])
await check('audit', '/audit', ['封禁 IP', 'admin'])
await check('modules', '/modules', ['SYN Flood 防护', '连接跟踪'])
await check('access', '/access', ['203.0.113.9'])
await check('l7', '/l7', ['GET /'])
await check('projects', '/projects', ['web-public'])
await check('geoip', '/geoip', ['威胁情报源'])
await check('rules', '/rules', ['edge-api-01'])
await check('settings', '/settings', ['eth0', '0.4.6'])

// access tabs
await page.goto(base + '/#/access', { waitUntil: 'load' })
await page.waitForTimeout(1200)
await page.getByRole('button', { name: /白名单/ }).click()
await page.waitForTimeout(200)
const white = await page.evaluate(() => document.body.innerText)
results['access-whitelist'] = { ok: white.includes('10.0.0.0/8') }
await page.getByRole('button', { name: /端口 ACL/ }).click()
await page.waitForTimeout(200)
const acl = await page.evaluate(() => document.body.innerText)
results['access-acl'] = { ok: acl.includes('3306') }

// IP detail drawer uses /api/ip-detail
await page.goto(base + '/#/attacks', { waitUntil: 'load' })
await page.waitForTimeout(1200)
await page.getByText('203.0.113.9').first().click()
await page.waitForTimeout(900)
const drawer = await page.evaluate(() => document.querySelector('.drawer')?.innerText || '')
results['ip-drawer'] = { ok: drawer.includes('恶意') && drawer.includes('9,812,443'), sample: drawer.slice(0, 60) }

const ok = Object.values(results).every((r) => r.ok)
console.log(JSON.stringify({ ok, live: results.overview.live, results, pageErrors: pageErrors.slice(0, 5) }, null, 2))
await browser.close()
process.exit(ok ? 0 : 1)
