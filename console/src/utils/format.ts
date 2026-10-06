export function fmtInt(n: number | undefined | null): string {
  if (n === undefined || n === null || Number.isNaN(n)) return '—'
  return Math.round(n).toLocaleString('en-US')
}
export function fmtCompact(n: number | undefined | null): { value: string; unit: string } {
  if (n === undefined || n === null) return { value: '—', unit: '' }
  const abs = Math.abs(n)
  if (abs >= 1e9) return { value: (n / 1e9).toFixed(2), unit: 'B' }
  if (abs >= 1e6) return { value: (n / 1e6).toFixed(2), unit: 'M' }
  if (abs >= 1e3) return { value: (n / 1e3).toFixed(1), unit: 'K' }
  return { value: String(Math.round(n)), unit: '' }
}
export function fmtRate(n: number | undefined | null): string {
  const { value, unit } = fmtCompact(n)
  return `${value}${unit}/s`
}
export function fmtPercent(n: number, digits = 2): string {
  return `${(n * 100).toFixed(digits)}%`
}
export function fmtTime(ns: number): string {
  const d = new Date(ns / 1e6)
  return d.toLocaleTimeString('zh-CN', { hour12: false })
}
export function fmtDateTime(ns: number): string {
  const d = new Date(ns / 1e6)
  const pad = (x: number) => String(x).padStart(2, '0')
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())} ${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`
}
export function fmtAgo(ns: number): string {
  const diff = Date.now() - ns / 1e6
  if (diff < 1000) return '刚刚'
  if (diff < 60_000) return `${Math.floor(diff / 1000)} 秒前`
  if (diff < 3_600_000) return `${Math.floor(diff / 60_000)} 分钟前`
  if (diff < 86_400_000) return `${Math.floor(diff / 3_600_000)} 小时前`
  return `${Math.floor(diff / 86_400_000)} 天前`
}
export function fmtDuration(ns: number): string {
  if (!ns) return '永久'
  const s = Math.max(0, Math.round((ns / 1e6 - Date.now()) / 1000))
  if (s >= 3600) return `${Math.floor(s / 3600)}h ${Math.floor((s % 3600) / 60)}m`
  if (s >= 60) return `${Math.floor(s / 60)}m ${s % 60}s`
  return `${s}s`
}
export const protocolTag = (p: string) => (p === 'TCP' ? 'tag-info' : p === 'UDP' ? 'tag-violet' : 'tag-warn')
