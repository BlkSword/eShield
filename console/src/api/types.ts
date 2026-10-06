export interface Stats {
  total_packets: number
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
  [k: string]: unknown
}
