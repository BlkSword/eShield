export interface Stats {
  total_packets: number
  /** XDP 是否真的挂在网卡上（v0.4.8） */
  xdp_attached?: boolean
  /** native / generic / unknown */
  xdp_mode?: string
  total_passed: number
  total_dropped: number
  current_pps: number
  current_dps: number
  blacklist_blocked: number
  rate_limited: number
  syn_flood_blocked: number
  l7_blocked: number
  adaptive_blocked: number
  udp_flood_blocked: number
  icmp_flood_blocked: number
  geoip_blocked: number
  conn_track_blocked: number
  /** 协议 + 目的端口聚合限速拦截（v0.5.0，防伪造源绕过） */
  port_rate_blocked: number
  /** 非首片分片策略拦截（v0.5.0） */
  fragment_blocked: number
  tcp_rst_sent: number
  tcp_rst_fail: number
  tcp_rst_attempt: number
  tcp_dropped: number
  udp_dropped: number
  icmp_dropped: number
  other_dropped: number
  top_attackers: { ip: string; count: number }[]
  top_ports: { port: number; count: number }[]
  trust_trusted: number
  trust_neutral: number
  trust_suspicious: number
  trust_malicious: number
  danger_level: number
}

export interface AttackEvent {
  id: string
  timestamp_ns: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  action: 'DROP' | 'PASS' | string
  rule: string
  reason: string
  length: number
  interface: string
}

export interface PacketSample {
  id: string
  timestamp_ns: number
  src_ip: string
  dst_ip: string
  src_port: number
  dst_port: number
  protocol: string
  action: string
  length: number
  tcp_flags?: string
  payload_preview?: string
}

export interface AuditEntry {
  id: string
  timestamp_ns: number
  actor: string
  action: string
  target: string
  detail: string
  source_ip: string
}

export interface ModuleState {
  id: string
  name: string
  group: string
  description: string
  enabled: boolean
  statsKey?: keyof Stats
  fields: { key: string; label: string; value: number | boolean; type: 'switch' | 'number' }[]
  /** Patch payload for /api/config when this module is toggled. */
  patch?: Record<string, unknown>
}

export interface BlockEntry {
  ip: string
  reason: string
  /** 首次触发后其它模块叠加的原因（空字符串表示无叠加） */
  last_reason?: string
  origin: string
  created_ns: number
  expires_ns: number
  hits: number
}

export interface WhitelistEntry {
  cidr: string
  note: string
}

export interface PortAclEntry {
  protocol: string
  dport: string
  action: string
}

export interface L7Pattern {
  pattern: string
  mask?: string
}

export interface ProtectionProject {
  name: string
  description: string
  protocol: string
  dport: string
  target_ips: string[]
  enabled_modules: string[]
  action: 'defend' | 'pass' | 'drop'
  enabled: boolean
}

export interface SeriesPoint {
  t: number
  pps: number
  dps: number
  passed: number
  dropped: number
}

/** 访问令牌角色（v0.5.0）：admin 可写，readonly 只读。 */
export type Role = 'admin' | 'readonly'
/** 非首片分片策略（v0.5.0）：pass 放行 / rate_limit 计入聚合限速 / drop 直接丢弃。 */
export type FragmentPolicy = 'pass' | 'rate_limit' | 'drop'
/** 限速超限处置（v0.5.0）：hard 拉黑源 IP，soft 只丢弃不拉黑（适合 NAT 出口）。 */
export type RateLimitBlockMode = 'hard' | 'soft'

/** 按协议 + 目的端口聚合限速的运行时参数。 */
export interface PortRateLimitConfig {
  enabled: boolean
  threshold: number
  tick_ms: number
}

export interface ConfigSnapshot {
  version: string
  interface: string
  log_level: string
  web_bind: string
  store_path: string
  rate_limit_enabled: boolean
  syn_proxy_enabled: boolean
  l7_scan_enabled: boolean
  udp_flood_enabled: boolean
  icmp_flood_enabled: boolean
  geoip_enabled: boolean
  geoip_default_action: number
  conn_track_enabled: boolean
  conn_track_threshold: number
  conn_track_window_ms: number
  trust_enabled: boolean
  tcp_reset_on_drop: boolean
  danger_level: number
  protection_projects_enabled: boolean
  /** 非首片分片策略（v0.5.0） */
  fragment_policy: FragmentPolicy
  /** 限速超限处置模式（v0.5.0） */
  rate_limit_block_mode: RateLimitBlockMode
  /** 审计日志文件路径（文件审计关闭时可能为缺省值） */
  audit_path?: string
  /** 文件审计后端是否启用（/api/audit/verify 依赖它） */
  audit_enabled?: boolean
  /** 按协议 + 目的端口聚合限速参数（v0.5.0 默认启用） */
  port_rate_limit?: PortRateLimitConfig
  [k: string]: unknown
}

/** eBPF map 单张表的水位（v0.5.0 /api/map-usage）。 */
export interface MapUsageEntry {
  name: string
  /** aya map 类型，如 LruHash / PerCpuArray / RingBuf */
  type: string
  entries: number
  max: number
  /** entries / max；max 为 0（未采集到上限）时为 0 */
  ratio: number
}

export interface MapUsage {
  maps: MapUsageEntry[]
  /** 使用率告警阈值（默认 0.8） */
  warn_threshold: number
  /** 最近一次采样的单调时钟纳秒（0 表示尚未采样） */
  sampled_ns: number
}

/** 审计哈希链校验结果（v0.5.0 /api/audit/verify）。 */
export interface AuditVerifyReport {
  ok: boolean
  /** false 表示文件审计后端未启用，此时 checked/first_bad_seq 无意义 */
  enabled?: boolean
  message?: string
  checked?: number
  /** 首个哈希链断点的记录序号；null 表示整条链完整 */
  first_bad_seq?: number | null
  path?: string
}
