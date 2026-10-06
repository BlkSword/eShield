import * as mock from './mock'
import type {
  AttackEvent, AuditEntry, BlockEntry, ConfigSnapshot, L7Pattern, ModuleState,
  PacketSample, PortAclEntry, ProtectionProject, SeriesPoint, Stats, WhitelistEntry,
} from './types'

const TOKEN_KEY = 'eshield-token'
const params = new URLSearchParams(location.search)
const forced = params.get('mock') === '1' ? 'mock' : params.get('live') === '1' ? 'live' : 'auto'

export const state = {
  mode: forced as 'auto' | 'mock' | 'live',
  live: false,
  token: localStorage.getItem(TOKEN_KEY) || '',
}

export function getToken() { return state.token }
export function setToken(t: string) {
  state.token = t
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

let mockStats = mock.makeStats()
let mockSeries = mock.makeSeries()
let mockEvents = mock.makeAttackEvents()
let mockPackets = mock.makePacketSamples()
let mockAudit = mock.makeAudit()
let mockBlocks = mock.makeBlacklist()
let mockL7 = [...mock.l7Patterns]
let mockProjects = [...mock.projects]
let mockWhitelist = [...mock.whitelist]
let mockAcl = [...mock.portAcl]
let mockConfig = mock.makeConfig()

async function raw<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (state.token) headers.Authorization = `Bearer ${state.token}`
  const res = await fetch(path, { ...init, headers: { ...headers, ...(init?.headers || {}) } })
  if (res.status === 401) throw new Error('unauthorized')
  if (!res.ok) throw new Error(`HTTP ${res.status}`)
  const text = await res.text()
  return (text ? JSON.parse(text) : null) as T
}

async function liveOrMock<T>(path: string, fallback: () => T, init?: RequestInit): Promise<T> {
  if (state.mode === 'mock') return fallback()
  try {
    const value = await raw<T>(path, init)
    state.live = true
    return value
  } catch (err) {
    if (state.mode === 'live') throw err
    state.live = false
    return fallback()
  }
}

export const api = {
  isLive: () => state.live,
  async stats(): Promise<Stats> {
    return liveOrMock('/api/stats', () => ({ ...mockStats, current_pps: mockStats.current_pps + (Math.random() * 40000 - 20000) | 0 }))
  },
  async series(): Promise<SeriesPoint[]> {
    return liveOrMock('/api/metrics/series?hours=24', () => {
      mockSeries = mock.makeSeries()
      return mockSeries
    })
  },
  async attackEvents(): Promise<AttackEvent[]> {
    return liveOrMock('/api/attack-events?limit=200', () => {
      mockEvents = mock.makeAttackEvents()
      return mockEvents
    })
  },
  async packets(): Promise<PacketSample[]> {
    return liveOrMock('/api/packets?limit=200', () => mockPackets)
  },
  async audit(): Promise<AuditEntry[]> {
    return liveOrMock('/api/audit?limit=200', () => mockAudit)
  },
  async blacklist(): Promise<BlockEntry[]> {
    return liveOrMock('/api/blacklist', () => mockBlocks)
  },
  async whitelist(): Promise<WhitelistEntry[]> {
    return liveOrMock('/api/whitelist', () => mockWhitelist)
  },
  async portAcl(): Promise<PortAclEntry[]> {
    return liveOrMock('/api/port-acl', () => mockAcl)
  },
  async l7Patterns(): Promise<L7Pattern[]> {
    return liveOrMock('/api/l7-patterns', () => mockL7)
  },
  async projects(): Promise<ProtectionProject[]> {
    return liveOrMock('/api/protection-projects', () => mockProjects)
  },
  async config(): Promise<ConfigSnapshot> {
    return liveOrMock('/api/config', () => mockConfig)
  },
  async modules(stats: Stats): Promise<ModuleState[]> {
    return liveOrMock('/api/protection-modules', () => mock.makeModules(stats))
  },
  async block(ip: string, duration_s = 0) {
    if (state.mode === 'mock' || !state.live) {
      mockBlocks = [{ ip, reason: '手动封禁', origin: 'api', created_ns: Date.now() * 1e6, expires_ns: duration_s ? (Date.now() + duration_s * 1000) * 1e6 : 0, hits: 0 }, ...mockBlocks]
      return { ok: true }
    }
    return raw('/api/blacklist', { method: 'POST', body: JSON.stringify({ ip, duration_s }) })
  },
  async unblock(ip: string) {
    if (state.mode === 'mock' || !state.live) {
      mockBlocks = mockBlocks.filter((b) => b.ip !== ip)
      return { ok: true }
    }
    return raw('/api/blacklist', { method: 'DELETE', body: JSON.stringify({ ip }) })
  },
  async patchConfig(patch: Record<string, unknown>) {
    if (state.mode === 'mock' || !state.live) {
      mockConfig = { ...mockConfig, ...(patch as Partial<ConfigSnapshot>) }
      return { ok: true }
    }
    return raw('/api/config', { method: 'PATCH', body: JSON.stringify(patch) })
  },
  async saveL7(patterns: L7Pattern[]) {
    if (state.mode === 'mock' || !state.live) { mockL7 = patterns; return { ok: true } }
    return raw('/api/l7-patterns', { method: 'POST', body: JSON.stringify({ patterns }) })
  },
  async saveProjects(projects: ProtectionProject[]) {
    if (state.mode === 'mock' || !state.live) { mockProjects = projects; return { ok: true } }
    return raw('/api/protection-projects', { method: 'POST', body: JSON.stringify({ projects }) })
  },
  async addWhitelist(cidr: string) {
    if (state.mode === 'mock' || !state.live) { mockWhitelist = [...mockWhitelist, { cidr, note: '手动添加' }]; return { ok: true } }
    return raw('/api/whitelist', { method: 'POST', body: JSON.stringify({ cidr }) })
  },
  async delWhitelist(cidr: string) {
    if (state.mode === 'mock' || !state.live) { mockWhitelist = mockWhitelist.filter((w) => w.cidr !== cidr); return { ok: true } }
    return raw('/api/whitelist', { method: 'DELETE', body: JSON.stringify({ cidr }) })
  },
  async savePortAcl(items: PortAclEntry[]) {
    if (state.mode === 'mock' || !state.live) { mockAcl = items; return { ok: true } }
    return raw('/api/port-acl', { method: 'POST', body: JSON.stringify({ items }) })
  },
  async reloadConfig() {
    if (state.mode === 'mock' || !state.live) return { ok: true }
    return raw('/api/config/reload', { method: 'POST' })
  },
}
