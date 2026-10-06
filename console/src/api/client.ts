import * as mock from './mock'
import type {
  AttackEvent, AuditEntry, BlockEntry, ConfigSnapshot, L7Pattern, ModuleState,
  PacketSample, PortAclEntry, ProtectionProject, SeriesPoint, Stats, WhitelistEntry,
} from './types'

const TOKEN_KEY = 'eshield-token'
const params = new URLSearchParams(location.search)
const initialMode = params.get('mock') === '1'
  ? 'mock'
  : params.get('live') === '1'
    ? 'live'
    : location.protocol.startsWith('http') ? 'auto' : 'mock'

export const state = {
  mode: initialMode as 'auto' | 'mock' | 'live',
  live: false,
  token: localStorage.getItem(TOKEN_KEY) || '',
}

export function getToken() { return state.token }
export function setToken(t: string) {
  state.token = t
  if (t) localStorage.setItem(TOKEN_KEY, t)
  else localStorage.removeItem(TOKEN_KEY)
}

// ---------------------------------------------------------------- mock state
let mockSeries = mock.makeSeries()
let mockEvents = mock.makeAttackEvents()
let mockPackets = mock.makePacketSamples()
let mockAudit = mock.makeAudit()
let mockBlocks = mock.makeBlacklist()
let mockWhitelist = [...mock.whitelist]
let mockAcl = [...mock.portAcl]
let mockL7 = [...mock.l7Patterns]
let mockProjects = [...mock.projects]
let mockConfig = mock.makeConfig()
let mockModules = mock.makeModules(mock.makeStats())

// -------------------------------------------------------------- normalizers
const PROTO_NAMES: Record<number, string> = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMP' }
const RULE_NAMES: Record<number, string> = {
  1: '黑名单', 2: '速率限制', 3: 'SYN Flood', 4: 'L7 指纹', 5: '自适应', 6: '手动封禁',
  7: '端口 ACL', 8: 'UDP Flood', 9: 'ICMP Flood', 10: 'GeoIP', 11: '威胁情报', 12: '防护项目',
}

function protoName(v: number | string | undefined): string {
  if (typeof v === 'string') return v.toUpperCase()
  return PROTO_NAMES[v ?? 0] ?? 'OTHER'
}
function actionName(v: number | string | undefined): string {
  if (typeof v === 'string') return v
  return v === 1 ? 'DROP' : v === 2 ? 'PASS' : v === 3 ? 'TX' : 'DROP'
}

function modulePatch(id: string, enabled: boolean): Record<string, unknown> {
  switch (id) {
    case 'syn_flood': return { syn_proxy_enabled: enabled }
    case 'udp_flood': return { udp_flood_enabled: enabled }
    case 'icmp_flood': return { icmp_flood_enabled: enabled }
    case 'l7_scan': return { l7_scan_enabled: enabled }
    case 'geoip': return { geoip_enabled: enabled }
    case 'conn_track': return { conn_track_enabled: enabled }
    case 'tcp_reset': return { tcp_reset_on_drop: enabled }
    case 'trust_score': return { trust_enabled: enabled }
    case 'rate_limit': return { rate_limit_enabled: enabled }
    case 'port_rate_limit':
      return { port_rate_limit: { enabled, threshold: 2000, tick_ms: 100, decay_num: 7, decay_den: 8, block_duration_s: 300 } }
    case 'adaptive':
      return { adaptive: { enabled, threshold: 10, window_s: 5, block_duration_s: 300 } }
    default: return {}
  }
}

function normalizeModule(m: any): ModuleState {
  return {
    id: String(m.id),
    name: String(m.name ?? m.id),
    group: String(m.category ?? m.group ?? '其他'),
    description: String(m.description ?? ''),
    enabled: !!m.enabled,
    statsKey: m.stats_key || m.statsKey || undefined,
    fields: (m.editable_fields || m.fields || [])
      .filter((f: any) => f && f.type !== 'readonly')
      .map((f: any) => ({
        key: String(f.id ?? f.key),
        label: String(f.label ?? f.id ?? f.key),
        value: f.value,
        type: f.type === 'switch' ? 'switch' : 'number',
      })),
    patch: modulePatch(String(m.id), !!m.enabled),
  }
}

function normalizeSeries(raw: any): SeriesPoint[] {
  const list = Array.isArray(raw) ? raw : (raw?.series || [])
  return list.map((p: any) => {
    const ns: number | undefined = p.timestamp_ns
    const ms = ns ? Math.round(ns / 1e6) : Number(p.timestamp ?? 0) * 1000
    const dropped = Number(p.dps ?? p.dropped ?? 0)
    const pps = Number(p.pps ?? 0)
    return { t: ms, pps, dps: dropped, passed: Math.max(0, pps - dropped), dropped }
  })
}

function normalizeEvents(raw: any): AttackEvent[] {
  const list = Array.isArray(raw) ? raw : (raw?.events || [])
  return list.map((e: any, i: number) => {
    const rule = e.rule_name || RULE_NAMES[Number(e.rule_id)] || '未知'
    return {
      id: e.id || `evt-${e.timestamp_ns ?? i}-${i}`,
      timestamp_ns: Number(e.timestamp_ns ?? Date.now() * 1e6),
      src_ip: String(e.src_ip ?? '—'),
      dst_ip: String(e.dst_ip ?? '—'),
      src_port: Number(e.src_port ?? 0),
      dst_port: Number(e.dst_port ?? 0),
      protocol: protoName(e.protocol),
      action: actionName(e.action),
      rule,
      reason: e.reason || rule,
      length: Number(e.length ?? e.packet_len ?? 0),
      interface: String(e.interface ?? 'eth0'),
    }
  })
}

function normalizePackets(raw: any): PacketSample[] {
  const list = Array.isArray(raw) ? raw : (raw?.entries || raw?.packets || [])
  return list.map((e: any, i: number) => ({
    id: e.id || `pkt-${e.timestamp_ns ?? i}-${i}`,
    timestamp_ns: Number(e.timestamp_ns ?? Date.now() * 1e6),
    src_ip: String(e.src_ip ?? '—'),
    dst_ip: String(e.dst_ip ?? '—'),
    src_port: Number(e.src_port ?? 0),
    dst_port: Number(e.dst_port ?? 0),
    protocol: protoName(e.protocol),
    action: actionName(e.action),
    length: Number(e.packet_len ?? e.length ?? 0),
    tcp_flags: e.tcp_flags,
    payload_preview: e.payload_hex ? e.payload_hex.slice(0, 48) : undefined,
  }))
}

const AUDIT_LABELS: Record<string, string> = {
  BlockIp: '封禁 IP', UnblockIp: '解除封禁', AllowCidr: '添加白名单', DisallowCidr: '移除白名单',
  ReloadConfig: '重载配置', PatchConfig: '修改配置', Start: '启动', Stop: '停止',
  Login: '登录', ResetToken: '重置令牌',
}

function normalizeAudit(raw: any): AuditEntry[] {
  const list = Array.isArray(raw) ? raw : (raw?.entries || [])
  return list.map((e: any, i: number) => {
    const detail = e.detail ?? {}
    const target = detail.ip || detail.cidr || (detail.count ? `${detail.count} 条` : '—')
    return {
      id: e.id || `aud-${i}`,
      timestamp_ns: e.timestamp_ns ?? (Date.parse(e.timestamp) * 1e6 || Date.now() * 1e6),
      actor: String(e.actor ?? 'system'),
      action: AUDIT_LABELS[e.action] || String(e.action ?? ''),
      target: String(target),
      detail: typeof detail === 'string' ? detail : JSON.stringify(detail ?? {}),
      source_ip: String(e.source_ip ?? '—'),
    }
  })
}

function normalizeBlocks(raw: any): BlockEntry[] {
  const list = Array.isArray(raw) ? raw : (raw?.entries || raw?.blacklist || [])
  return list.map((b: any) => ({
    ip: String(b.ip ?? ''),
    reason: String(b.reason ?? ''),
    origin: String(b.origin ?? ''),
    created_ns: Number(b.created_ns ?? Date.now() * 1e6),
    expires_ns: Number(b.expires_ns ?? 0),
    hits: Number(b.hits ?? b.hit_count ?? 0),
  }))
}

function normalizeWhitelist(raw: any): WhitelistEntry[] {
  const list = Array.isArray(raw) ? raw : (raw?.entries || raw?.whitelist || [])
  return list.map((w: any) => ({ cidr: String(w.cidr ?? w), note: String(w.note ?? '') }))
}

// ---------------------------------------------------------------- transport
async function raw<T>(path: string, init?: RequestInit): Promise<T> {
  const headers: Record<string, string> = { 'Content-Type': 'application/json' }
  if (state.token) headers.Authorization = `Bearer ${state.token}`
  const res = await fetch(path, { ...init, headers: { ...headers, ...(init?.headers || {}) } })
  if (!res.ok) throw new Error(res.status === 401 ? 'unauthorized' : `HTTP ${res.status}`)
  const text = await res.text()
  return (text ? JSON.parse(text) : null) as T
}

/// Read path with auto fallback. Returns null when the caller should use mock data.
async function fetchOrNull<T>(path: string): Promise<T | null> {
  if (state.mode === 'mock') return null
  try {
    const value = await raw<T>(path)
    state.live = true
    return value
  } catch (err) {
    if (state.mode === 'live') throw err
    state.live = false
    return null
  }
}

/// Mutations never silently fall back; demo mode (file:// or ?mock=1) mutates local state.
async function mutate(path: string, body: unknown): Promise<void> {
  if (state.mode !== 'mock') {
    try {
      await raw(path, { method: 'POST', body: JSON.stringify(body) })
      state.live = true
      return
    } catch (err) {
      if (state.mode === 'live') throw err
      state.live = false
    }
  }
}

export const api = {
  isLive: () => state.live,

  async stats(): Promise<Stats> {
    const r = await fetchOrNull<Stats>('/api/stats')
    return r ?? mock.makeStats()
  },
  async series(): Promise<SeriesPoint[]> {
    const r = await fetchOrNull<any>('/api/metrics/series?duration_s=86400')
    return r ? normalizeSeries(r) : (mockSeries = mock.makeSeries())
  },
  async attackEvents(): Promise<AttackEvent[]> {
    const r = await fetchOrNull<any>('/api/attack-events?limit=200')
    return r ? normalizeEvents(r) : (mockEvents = mock.makeAttackEvents())
  },
  async packets(): Promise<PacketSample[]> {
    const r = await fetchOrNull<any>('/api/packets?limit=200')
    return r ? normalizePackets(r) : mockPackets
  },
  async audit(): Promise<AuditEntry[]> {
    const r = await fetchOrNull<any>('/api/audit?limit=200')
    return r ? normalizeAudit(r) : mockAudit
  },
  async blacklist(): Promise<BlockEntry[]> {
    const r = await fetchOrNull<any>('/api/blacklist')
    return r ? normalizeBlocks(r) : mockBlocks
  },
  async whitelist(): Promise<WhitelistEntry[]> {
    const r = await fetchOrNull<any>('/api/whitelist')
    return r ? normalizeWhitelist(r) : mockWhitelist
  },
  async portAcl(): Promise<PortAclEntry[]> {
    const r = await fetchOrNull<any>('/api/port-acl')
    const list = r ? (r.items || r) : mockAcl
    return list.map((a: any) => ({ protocol: String(a.protocol), dport: String(a.dport), action: String(a.action) }))
  },
  async l7Patterns(): Promise<L7Pattern[]> {
    const r = await fetchOrNull<any>('/api/l7-patterns')
    const list = r ? (r.patterns || r) : mockL7
    return list.map((p: any) => ({ pattern: String(p.pattern ?? ''), mask: p.mask || undefined }))
  },
  async projects(): Promise<ProtectionProject[]> {
    const r = await fetchOrNull<any>('/api/protection-projects')
    const list = r ? (r.projects || r) : mockProjects
    return list.map((p: any) => ({
      name: String(p.name ?? ''), description: String(p.description ?? ''),
      protocol: String(p.protocol ?? 'tcp'), dport: String(p.dport ?? ''),
      target_ips: (p.target_ips || []).map(String),
      enabled_modules: (p.enabled_modules || []).map(String),
      action: (p.action || 'defend') as ProtectionProject['action'],
      enabled: p.enabled ?? true,
    }))
  },
  async config(): Promise<ConfigSnapshot> {
    const r = await fetchOrNull<any>('/api/config')
    return (r ? { ...mockConfig, ...r } : mockConfig) as ConfigSnapshot
  },
  async modules(stats: Stats): Promise<ModuleState[]> {
    const r = await fetchOrNull<any>('/api/protection-modules')
    if (r) {
      const list = r.modules || r
      return list.map(normalizeModule)
    }
    if (!mockModules.length) mockModules = mock.makeModules(stats)
    return mockModules
  },

  async block(ip: string, duration_s = 0) {
    if (state.mode === 'mock') {
      mockBlocks = [{ ip, reason: '手动封禁', origin: 'api', created_ns: Date.now() * 1e6, expires_ns: duration_s ? (Date.now() + duration_s * 1000) * 1e6 : 0, hits: 0 }, ...mockBlocks]
      return { ok: true }
    }
    await raw('/api/blacklist', { method: 'POST', body: JSON.stringify({ ip, duration_s }) })
    return { ok: true }
  },
  async unblock(ip: string) {
    if (state.mode === 'mock') {
      mockBlocks = mockBlocks.filter((b) => b.ip !== ip)
      return { ok: true }
    }
    await raw('/api/blacklist', { method: 'DELETE', body: JSON.stringify({ ip }) })
    return { ok: true }
  },
  async addWhitelist(cidr: string) {
    if (state.mode === 'mock') {
      mockWhitelist = [...mockWhitelist, { cidr, note: '手动添加' }]
      return { ok: true }
    }
    await raw('/api/whitelist', { method: 'POST', body: JSON.stringify({ cidr }) })
    return { ok: true }
  },
  async delWhitelist(cidr: string) {
    if (state.mode === 'mock') {
      mockWhitelist = mockWhitelist.filter((w) => w.cidr !== cidr)
      return { ok: true }
    }
    await raw('/api/whitelist', { method: 'DELETE', body: JSON.stringify({ cidr }) })
    return { ok: true }
  },
  async savePortAcl(items: PortAclEntry[]) {
    if (state.mode === 'mock') { mockAcl = items; return { ok: true } }
    await raw('/api/port-acl', { method: 'POST', body: JSON.stringify({ items }) })
    return { ok: true }
  },
  async saveL7(patterns: L7Pattern[]) {
    if (state.mode === 'mock') { mockL7 = patterns; return { ok: true } }
    await raw('/api/l7-patterns', { method: 'POST', body: JSON.stringify({ patterns }) })
    return { ok: true }
  },
  async saveProjects(projects: ProtectionProject[]) {
    if (state.mode === 'mock') { mockProjects = projects; return { ok: true } }
    await raw('/api/protection-projects', { method: 'POST', body: JSON.stringify({ projects }) })
    return { ok: true }
  },
  async patchConfig(patch: Record<string, unknown>) {
    if (state.mode === 'mock') { mockConfig = { ...mockConfig, ...(patch as Partial<ConfigSnapshot>) }; return { ok: true } }
    await raw('/api/config', { method: 'PATCH', body: JSON.stringify(patch) })
    return { ok: true }
  },
  async patchModule(id: string, enabled: boolean) {
    const patch = modulePatch(id, enabled)
    if (state.mode === 'mock') {
      const m = mockModules.find((x) => x.id === id)
      if (m) m.enabled = enabled
      return { ok: true }
    }
    await raw('/api/config', { method: 'PATCH', body: JSON.stringify(patch) })
    return { ok: true }
  },
  async reloadConfig() {
    if (state.mode === 'mock') return { ok: true }
    await raw('/api/config/reload', { method: 'POST' })
    return { ok: true }
  },
  async reloadGeoIp() {
    if (state.mode === 'mock') return { ok: true }
    await raw('/api/geoip/reload', { method: 'POST' })
    return { ok: true }
  },
  async syncThreatIntel() {
    if (state.mode === 'mock') return { ok: true }
    await raw('/api/threat-intel/sync', { method: 'POST' })
    return { ok: true }
  },
  async hubStatus(): Promise<any | null> {
    return fetchOrNull<any>('/api/hub/status')
  },
  async hubNodes(): Promise<any[] | null> {
    const r = await fetchOrNull<any>('/api/hub/proxy/nodes')
    if (!r) return null
    return r.nodes || r
  },
  async ipDetail(ip: string): Promise<any | null> {
    return fetchOrNull<any>(`/api/ip-detail?ip=${encodeURIComponent(ip)}`)
  },
  async ipSeries(ip: string): Promise<SeriesPoint[]> {
    const r = await fetchOrNull<any>(`/api/ip-series?ip=${encodeURIComponent(ip)}&duration_s=3600`)
    if (!r) return []
    return (r.series || []).map((p: any) => {
      const drops = Number(p.drop_count ?? 0)
      const passes = Number(p.pass_count ?? 0)
      return { t: Number(p.timestamp ?? 0) * 1000, pps: passes, dps: drops, passed: passes, dropped: drops }
    })
  },
}
