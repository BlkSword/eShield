import type {
  AttackEvent, AuditEntry, BlockEntry, ConfigSnapshot, L7Pattern, ModuleState,
  PacketSample, PortAclEntry, ProtectionProject, SeriesPoint, Stats, WhitelistEntry,
} from './types'

// Mock data mirrors values observed during the 2026-10 extreme test on
// virtio_net + native XDP so the sample reads like a real deployment.
const now = Date.now()
const ns = (msAgo: number) => (now - msAgo) * 1_000_000

const protocols = ['TCP', 'UDP', 'ICMP']
const rules = ['blacklist', 'syn_flood', 'udp_flood', 'icmp_flood', 'l7_pattern', 'rate_limit', 'geoip', 'conn_track', 'project_policy', 'port_acl']
const reasons: Record<string, string> = {
  blacklist: '命中动态/静态黑名单',
  syn_flood: 'SYN 半连接超阈值',
  udp_flood: 'UDP 单源速率超阈值',
  icmp_flood: 'ICMP 单源速率超阈值',
  l7_pattern: '命中 L7 指纹',
  rate_limit: '全局速率限制',
  geoip: 'GeoIP 区域策略',
  conn_track: '连接跟踪半连接超限',
  project_policy: '防护项目 DROP',
  port_acl: '端口 ACL 拒绝',
}
const attackerIps = [
  '172.23.83.40', '172.23.83.41', '45.83.12.77', '103.145.9.21', '185.220.101.4',
  '62.102.148.68', '91.240.118.22', '141.98.10.63', '5.188.206.14', '80.94.95.31',
]

export function makeStats(boost = 0): Stats {
  return {
    total_packets: 3_284_915_204 + boost,
    total_passed: 3_271_006_118 + boost,
    total_dropped: 13_909_086,
    current_pps: 1_482_310 + boost,
    current_dps: 86_420,
    blacklist_blocked: 9_812_443,
    rate_limited: 1_204_880,
    syn_flood_blocked: 1_876_442,
    l7_blocked: 344_902,
    adaptive_blocked: 18_220,
    udp_flood_blocked: 12,
    icmp_flood_blocked: 15,
    geoip_blocked: 402_188,
    conn_track_blocked: 218_336,
    tcp_rst_sent: 0,
    tcp_rst_fail: 0,
    tcp_rst_attempt: 0,
    tcp_dropped: 11_920_446,
    udp_dropped: 1_502_331,
    icmp_dropped: 486_309,
    other_dropped: 0,
    top_attackers: attackerIps.map((ip, i) => ({ ip, count: Math.round(1_820_000 / (i + 1.35)) })),
    top_ports: [
      { port: 80, count: 8_120_000 },
      { port: 443, count: 3_040_000 },
      { port: 22, count: 1_280_000 },
      { port: 53, count: 902_000 },
      { port: 3306, count: 430_000 },
    ],
    trust_trusted: 12_402,
    trust_neutral: 1_204,
    trust_suspicious: 388,
    trust_malicious: 96,
    danger_level: 2,
  }
}

export function makeSeries(points = 48): SeriesPoint[] {
  const out: SeriesPoint[] = []
  for (let i = points - 1; i >= 0; i--) {
    const t = now - i * 30 * 60 * 1000
    const phase = Math.sin((points - i) / 5)
    const spike = i > 30 && i < 40 ? 1.9 : 1
    const pps = Math.round((900_000 + phase * 220_000 + Math.random() * 90_000) * spike)
    const dropped = Math.round(pps * (0.018 + Math.abs(phase) * 0.012) * spike)
    out.push({ t, pps, dps: dropped, passed: pps - dropped, dropped })
  }
  return out
}

export function makeAttackEvents(n = 120): AttackEvent[] {
  const out: AttackEvent[] = []
  for (let i = 0; i < n; i++) {
    const rule = rules[i % rules.length]
    const proto = protocols[i % protocols.length]
    const ip = attackerIps[i % attackerIps.length]
    const blocked = rule !== 'rate_limit' || i % 3 !== 0
    out.push({
      id: `evt-${String(i).padStart(6, '0')}`,
      timestamp_ns: ns(i * 7_400 + Math.floor(Math.random() * 3000)),
      src_ip: ip,
      dst_ip: '172.23.83.42',
      src_port: 1024 + ((i * 137) % 60000),
      dst_port: [80, 443, 22, 53, 3306][i % 5],
      protocol: proto,
      action: blocked ? 'DROP' : 'PASS',
      rule,
      reason: reasons[rule],
      length: 60 + (i % 12) * 4,
      interface: 'eth0',
    })
  }
  return out
}

export function makePacketSamples(n = 80): PacketSample[] {
  return makeAttackEvents(n).map((e, i) => ({
    id: `pkt-${String(i).padStart(6, '0')}`,
    timestamp_ns: e.timestamp_ns,
    src_ip: e.src_ip,
    dst_ip: e.dst_ip,
    src_port: e.src_port,
    dst_port: e.dst_port,
    protocol: e.protocol,
    action: e.action,
    length: e.length,
    tcp_flags: e.protocol === 'TCP' ? ['SYN', 'SYN ACK', 'ACK', 'PSH ACK', 'RST'][i % 5] : undefined,
    payload_preview:
      e.protocol === 'TCP' && i % 3 === 0
        ? '47 45 54 20 2f 61 70 69 2f 73 74 61 74 73 20 48   GET /api/stats H'
        : '00 01 02 03 04 05 06 07   ........',
  }))
}

export function makeAudit(n = 60): AuditEntry[] {
  const actions = ['Block IP', 'Unblock IP', 'Patch Config', 'Reload Config', 'Reset Token', 'Sync ThreatIntel', 'Update L7', 'Update Project', 'Login']
  return Array.from({ length: n }, (_, i) => ({
    id: `aud-${String(i).padStart(5, '0')}`,
    timestamp_ns: ns(i * 21_000 + 4000),
    actor: i % 5 === 0 ? 'api' : 'admin',
    action: actions[i % actions.length],
    target: i % 4 === 0 ? attackerIps[i % attackerIps.length] : '—',
    detail: i % 3 === 0 ? '{"duration_s":0}' : '{}',
    source_ip: i % 5 === 0 ? '127.0.0.1' : '172.23.83.41',
  }))
}

export function makeBlacklist(n = 24): BlockEntry[] {
  return Array.from({ length: n }, (_, i) => ({
    ip: attackerIps[i % attackerIps.length],
    reason: reasons[rules[i % rules.length]],
    origin: i % 3 === 0 ? 'adaptive' : i % 3 === 1 ? 'udp_flood' : 'api',
    created_ns: ns(i * 420_000),
    expires_ns: i % 4 === 0 ? 0 : ns(-(300_000 - i * 1000)),
    hits: 240_000 - i * 8_300,
  }))
}

export const whitelist: WhitelistEntry[] = [
  { cidr: '172.23.83.41/32', note: '管理跳板' },
  { cidr: '100.100.2.136/32', note: '云内网元数据' },
  { cidr: '100.100.2.138/32', note: '云内网 DNS' },
]

export const portAcl: PortAclEntry[] = [
  { protocol: 'tcp', dport: '22', action: 'accept' },
  { protocol: 'tcp', dport: '80,443', action: 'accept' },
  { protocol: 'tcp', dport: '3306', action: 'deny' },
  { protocol: 'udp', dport: '53', action: 'accept' },
]

export const l7Patterns: L7Pattern[] = [
  { pattern: 'GET /' },
  { pattern: 'POST /a' },
  { pattern: 'eval(' },
  { pattern: 'union s' },
]

export const projects: ProtectionProject[] = [
  {
    name: 'web-public', description: '公网 Web 入口，仅开启 L7 与端口限速',
    protocol: 'tcp', dport: '80,443', target_ips: ['172.23.83.42/32'],
    enabled_modules: ['l7_scan', 'rate_limit'], action: 'defend', enabled: true,
  },
  {
    name: 'ssh-admin', description: 'SSH 管理口，开启连接跟踪与速率限制',
    protocol: 'tcp', dport: '22', target_ips: ['172.23.83.42/32'],
    enabled_modules: ['conn_track', 'rate_limit'], action: 'defend', enabled: true,
  },
  {
    name: 'db-isolate', description: '数据库端口默认拒绝',
    protocol: 'tcp', dport: '3306', target_ips: ['172.23.83.42/32'],
    enabled_modules: [], action: 'drop', enabled: true,
  },
]

export function makeModules(stats: Stats): ModuleState[] {
  return [
    { id: 'rate_limit', name: '全局速率限制', group: '流量', description: '按源 IP 统计包速率，超过阈值后进入动态黑名单', enabled: true, statsKey: 'rate_limited', fields: [{ key: 'threshold', label: '阈值（包/窗口）', value: 200, type: 'number' }, { key: 'tick_ms', label: '窗口（ms）', value: 100, type: 'number' }, { key: 'block_duration_s', label: '封禁时长（s）', value: 300, type: 'number' }] },
    { id: 'port_rate_limit', name: '端口维度限速', group: '流量', description: '按协议 + 目的端口聚合限速，防换源 IP 绕过', enabled: false, fields: [{ key: 'threshold', label: '阈值（包/窗口）', value: 2000, type: 'number' }, { key: 'tick_ms', label: '窗口（ms）', value: 100, type: 'number' }] },
    { id: 'syn_proxy', name: 'SYN Proxy / Cookie', group: 'TCP', description: 'SYN Cookie 校验，缓解 SYN Flood', enabled: true, statsKey: 'syn_flood_blocked', fields: [] },
    { id: 'conn_track', name: '连接跟踪', group: 'TCP', description: '跟踪半连接数，超过阈值丢弃新 SYN', enabled: false, statsKey: 'conn_track_blocked', fields: [{ key: 'threshold', label: '半连接阈值', value: 100, type: 'number' }, { key: 'window_ms', label: '窗口（ms）', value: 10000, type: 'number' }] },
    { id: 'udp_flood', name: 'UDP Flood', group: 'UDP', description: '单源 UDP 速率限制，超限加入黑名单', enabled: true, statsKey: 'udp_flood_blocked', fields: [] },
    { id: 'icmp_flood', name: 'ICMP Flood', group: 'ICMP', description: '单源 ICMP Echo 速率限制', enabled: true, statsKey: 'icmp_flood_blocked', fields: [] },
    { id: 'l7_scan', name: 'L7 指纹', group: '应用层', description: '匹配 TCP 载荷前 8 字节，命中即丢弃', enabled: true, statsKey: 'l7_blocked', fields: [] },
    { id: 'geoip', name: 'GeoIP / ASN', group: '策略', description: '按国家/地区或 ASN 放行或阻断', enabled: false, statsKey: 'geoip_blocked', fields: [] },
    { id: 'adaptive', name: '自适应防护', group: '策略', description: '基于历史流量自动调整阈值与封禁', enabled: true, statsKey: 'adaptive_blocked', fields: [{ key: 'threshold', label: '触发阈值', value: 10, type: 'number' }, { key: 'window_s', label: '窗口（s）', value: 5, type: 'number' }] },
    { id: 'tcp_reset', name: 'TCP Reset', group: 'TCP', description: 'DROP 时向对端发送 RST', enabled: false, fields: [] },
    { id: 'trust_score', name: '信任评分', group: '策略', description: '按源 IP 历史行为累计信任分', enabled: true, fields: [] },
    { id: 'threat_intel', name: '威胁情报', group: '策略', description: '定时同步外部情报源并写入黑名单', enabled: false, fields: [] },
    { id: 'packet_log', name: '包日志采样', group: '可观测', description: '对 DROP 包进行 RingBuf 采样', enabled: true, fields: [{ key: 'sample_rate', label: '采样率 1/N', value: 16, type: 'number' }] },
  ]
}

export function makeConfig(): ConfigSnapshot {
  return {
    version: '0.4.6', interface: 'eth0', log_level: 'info', web_bind: '0.0.0.0:8720',
    store_path: '/var/lib/eshield/rules.redb', rate_limit_enabled: true,
    syn_proxy_enabled: true, l7_scan_enabled: true, udp_flood_enabled: true,
    icmp_flood_enabled: true, geoip_enabled: false, geoip_default_action: 0,
    conn_track_enabled: false, conn_track_threshold: 100, conn_track_window_ms: 10000,
    trust_enabled: true, tcp_reset_on_drop: false, danger_level: 2,
    protection_projects_enabled: true,
  }
}

export const hubNodes = [
  { name: 'edge-sgp-01', ip: '172.23.83.42', version: '0.4.6', status: 'online', policies: 18, last_seen: '6s' },
  { name: 'edge-hkg-02', ip: '172.23.83.41', version: '0.4.6', status: 'online', policies: 18, last_seen: '11s' },
  { name: 'edge-fra-03', ip: '10.8.0.14', version: '0.4.5', status: 'stale', policies: 12, last_seen: '4m' },
  { name: 'edge-sfo-04', ip: '10.9.1.22', version: '0.4.6', status: 'online', policies: 21, last_seen: '9s' },
]

export const threatFeeds = [
  { name: 'Spamhaus DROP', url: 'https://www.spamhaus.org/drop/drop.txt', interval: '1h', confidence: 90, entries: 1240, last: '12 分钟前' },
  { name: 'Emerging Threats', url: 'https://rules.emergingthreats.net/fwrules/', interval: '2h', confidence: 80, entries: 8430, last: '35 分钟前' },
  { name: 'Abuse.ch Feodo', url: 'https://feodotracker.abuse.ch/downloads/ipblocklist.txt', interval: '30m', confidence: 95, entries: 642, last: '8 分钟前' },
]
