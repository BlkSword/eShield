<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import LineChart from '../components/LineChart.vue'
import BarList from '../components/BarList.vue'
import KpiCard from '../components/KpiCard.vue'
import PanelCard from '../components/PanelCard.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api } from '../api/client'
import { store, toast } from '../stores/app'
import type { AttackEvent, ConfigSnapshot, MapUsage, MapUsageEntry, ModuleState } from '../api/types'
import { fmtAgo, fmtCompact, fmtInt, fmtPercent, fmtRate, fmtTime } from '../utils/format'
import { openDrawer } from '../stores/ui'

const router = useRouter()
const modules = ref<ModuleState[]>([])
const events = ref<AttackEvent[]>([])
const cfg = ref<ConfigSnapshot | null>(null)
const mapUsage = ref<MapUsage | null>(null)
const hub = ref<{ connected: boolean; url: string }>({ connected: false, url: '—' })
const range = ref<'15m' | '1h' | '24h'>('1h')

const s = computed(() => store.stats)
const dropRate = computed(() => (s.value && s.value.current_pps ? s.value.current_dps / s.value.current_pps : 0))
const ppsSpark = computed(() => store.series.map((p) => p.pps))
const dpsSpark = computed(() => store.series.map((p) => p.dps))
const peakPps = computed(() => (ppsSpark.value.length ? Math.max(...ppsSpark.value) : 0))

const chartSeries = computed(() => [
  { name: 'PPS', color: 'var(--accent)', data: ppsSpark.value },
  { name: 'DROP', color: 'var(--danger)', data: dpsSpark.value },
])
const chartLabels = computed(() => {
  const list = store.series
  if (!list.length) return ['', '']
  const out: string[] = []
  const n = 5
  for (let i = 0; i < n; i++) {
    const p = list[Math.round((i / (n - 1)) * (list.length - 1))]
    out.push(fmtTime(p.t * 1e6).slice(0, 5))
  }
  return out
})

const reasons = computed(() => {
  const v = s.value
  if (!v) return []
  return [
    { label: '黑名单', value: v.blacklist_blocked, tone: 'danger' as const },
    { label: '速率限制', value: v.rate_limited, tone: 'warn' as const },
    { label: 'SYN Flood', value: v.syn_flood_blocked, tone: 'accent' as const },
    { label: 'UDP Flood', value: v.udp_flood_blocked, tone: 'accent' as const },
    { label: 'L7 指纹', value: v.l7_blocked, tone: 'violet' as const },
    { label: 'GeoIP', value: v.geoip_blocked, tone: 'muted' as const },
  ]
    .filter((x) => x.value > 0)
    .sort((a, b) => b.value - a.value)
    .slice(0, 6)
})

const dangerLabel = computed(() => ['平稳', '关注', '警戒', '严重'][Math.min(s.value?.danger_level || 0, 3)])
const dangerTone = computed(() => (['ok', 'warn', 'warn', 'danger'] as const)[Math.min(s.value?.danger_level || 0, 3)])

const enabledModules = computed(() => modules.value.filter((m) => m.enabled).length)
const xdpMode = computed(() => {
  const v = (s.value as Record<string, unknown> | null)?.xdp_mode
  return typeof v === 'string' ? v : 'unknown'
})

// ------------------------------------------------- 防护有效性（v0.5.0）
const lifetimeDropRate = computed(() => {
  const v = s.value
  if (!v || !v.total_packets) return 0
  return v.total_dropped / v.total_packets
})
const dropProgress = computed(() => Math.max(2, Math.min(100, lifetimeDropRate.value * 100)))
const dropTone = computed(() => (lifetimeDropRate.value >= 0.1 ? 'danger' : lifetimeDropRate.value >= 0.03 ? 'warn' : 'ok'))
/** 各模块累计拦截量：与 /api/stats 字段一一对应（v0.5.0 新增PORT_RATE / FRAGMENT）。 */
const effectiveness = computed(() => {
  const v = s.value
  if (!v) return []
  return [
    { label: '黑名单', value: v.blacklist_blocked, tone: 'danger' as const },
    { label: 'SYN Flood', value: v.syn_flood_blocked, tone: 'accent' as const },
    { label: 'UDP Flood', value: v.udp_flood_blocked, tone: 'accent' as const },
    { label: 'ICMP Flood', value: v.icmp_flood_blocked, tone: 'accent' as const },
    { label: '速率限制', value: v.rate_limited, tone: 'warn' as const },
    { label: '端口聚合限速', value: v.port_rate_blocked || 0, tone: 'warn' as const },
    { label: '分片策略', value: v.fragment_blocked || 0, tone: 'warn' as const },
    { label: 'L7 指纹', value: v.l7_blocked, tone: 'violet' as const },
    { label: 'GeoIP', value: v.geoip_blocked, tone: 'muted' as const },
    { label: '连接跟踪', value: v.conn_track_blocked, tone: 'accent' as const },
    { label: '自适应', value: v.adaptive_blocked, tone: 'muted' as const },
  ]
})
const blockMode = computed(() => cfg.value?.rate_limit_block_mode || '—')
const blockModeHint = computed(() => {
  if (blockMode.value === 'soft') return 'soft：超限只丢弃、不拉黑源 IP，适合 NAT 出口'
  if (blockMode.value === 'hard') return 'hard：超限后把源 IP 加入动态黑名单（默认）'
  return '当前限速超限处置模式：hard / soft'
})

// ------------------------------------------------- 表项水位（v0.5.0）
// 服务端 sampled_ns 是 CLOCK_MONOTONIC 纳秒，浏览器无法直接换算墙钟时间：
// 以首次抓取为锚点，按单调时钟差值估算最近一次采样的本地时刻。
let sampleAnchorWall = 0
let sampleAnchorMono = 0
let sampleLastMono = 0
const mapSampledAt = ref(0)
const mapTotal = computed(() => mapUsage.value?.maps.length || 0)
const mapRows = computed<MapUsageEntry[]>(() =>
  [...(mapUsage.value?.maps || [])].sort((a, b) => b.ratio - a.ratio).slice(0, 12),
)
function mapRatioTone(m: MapUsageEntry): 'danger' | 'warn' | '' {
  const warnAt = mapUsage.value?.warn_threshold ?? 0.8
  if (m.ratio >= warnAt) return 'danger'
  if (m.ratio >= 0.6) return 'warn'
  return ''
}
function noteMapSample(sampledNs: number) {
  if (!sampledNs) return
  const wall = Date.now()
  if (!sampleAnchorMono) {
    sampleAnchorMono = sampledNs
    sampleAnchorWall = wall
    sampleLastMono = sampledNs
    mapSampledAt.value = wall
    return
  }
  if (sampledNs === sampleLastMono) return
  sampleLastMono = sampledNs
  // 单调时钟与墙钟同速，差值可直接换算到本地时间轴。
  mapSampledAt.value = Math.max(0, sampleAnchorWall + (sampledNs - sampleAnchorMono) / 1e6)
}
/** 条目数/上限用紧凑单位；dashWhenZero 用于上限为 0（尚未采集到上限）时显示 —。 */
function fmtCap(n: number, dashWhenZero = false) {
  if (dashWhenZero && !n) return '—'
  const c = fmtCompact(n)
  return c.value + c.unit
}
async function loadMapUsage() {
  const m = await api.mapUsage().catch(() => null)
  if (!m) return
  mapUsage.value = m
  noteMapSample(m.sampled_ns)
}

let mapTimer: number | undefined
onBeforeUnmount(() => {
  if (mapTimer) clearInterval(mapTimer)
})

async function loadMeta() {
  const [mods, evs, config, hubStatus] = await Promise.all([
    api.modules(s.value as never).catch(() => [] as ModuleState[]),
    api.attackEvents().catch(() => [] as AttackEvent[]),
    api.config().catch(() => null),
    api.hubStatus().catch(() => null),
  ])
  modules.value = mods
  events.value = evs.slice(0, 8)
  cfg.value = config
  if (hubStatus && typeof hubStatus === 'object') {
    const h = hubStatus as Record<string, unknown>
    hub.value = {
      connected: !!(h.connected ?? h.enabled ?? h.hub_connected),
      url: String(h.active_url || h.url || h.hub_url || '—'),
    }
  }
  loadMapUsage()
}

onMounted(() => {
  loadMeta()
  // map 条目数由服务端按 metrics_interval_s（默认 30s）采样，控制台 15s 拉一次即可。
  mapTimer = window.setInterval(loadMapUsage, 15000)
})

async function toggleModule(m: ModuleState, v: boolean) {
  m.enabled = v
  try {
    await api.patchModule(m.id, v)
    toast(`${m.name} 已${v ? '启用' : '停用'}`, '运行时生效，无需重启', v ? 'ok' : 'warn')
  } catch (e) {
    m.enabled = !v
    toast('切换失败', String(e), 'danger')
  }
}
function moduleStat(m: ModuleState) {
  if (!m.statsKey || !s.value) return '—'
  const c = fmtCompact(s.value[m.statsKey] as number)
  return c.value + c.unit
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">总览</div>
      <div class="page-meta">
        更新于 <span class="mono">{{ store.lastUpdated ? fmtTime(store.lastUpdated * 1e6) : '—' }}</span> · 每 3s 自动刷新
      </div>
      <div class="page-actions">
        <div class="segmented">
          <button v-for="r in (['15m', '1h', '24h'] as const)" :key="r" :class="{ active: range === r }" @click="range = r">
            {{ r === '15m' ? '15 分钟' : r === '1h' ? '1 小时' : '24 小时' }}
          </button>
        </div>
        <button class="btn btn-sm" @click="router.push('/attacks')">查看攻击事件</button>
      </div>
    </div>

    <div class="kpis">
      <KpiCard label="当前 PPS" :value="s?.current_pps || 0" format="int" :spark="ppsSpark" tone="accent" :foot="`峰值 ${fmtRate(peakPps)}`" />
      <KpiCard label="当前 DROP" :value="s?.current_dps || 0" format="int" :spark="dpsSpark" tone="danger" :foot="`丢弃率 ${fmtPercent(dropRate)}`" />
      <KpiCard label="累计处理" :value="s?.total_packets || 0" :foot="`放行 ${fmtCompact(s?.total_passed || 0).value}${fmtCompact(s?.total_passed || 0).unit}`" />
      <KpiCard label="累计拦截" :value="s?.total_dropped || 0" :foot="`黑名单 ${fmtCompact(s?.blacklist_blocked || 0).value}${fmtCompact(s?.blacklist_blocked || 0).unit}`" />
      <KpiCard
        label="危险等级"
        :value="'L' + (s?.danger_level || 0)"
        format="raw"
        :tone="dangerTone"
        :foot="`${dangerLabel} · 恶意源 ${fmtInt(s?.trust_malicious || 0)}`"
      />
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="流量趋势" :sub="`近 ${range === '15m' ? '15 分钟' : range === '1h' ? '1 小时' : '24 小时'} · 10s 粒度`">
        <template #actions>
          <div class="legend">
            <span><i style="background: var(--accent)"></i>PPS</span>
            <span><i style="background: var(--danger)"></i>DROP</span>
          </div>
        </template>
        <LineChart :series="chartSeries" :labels="chartLabels" :height="208" />
      </PanelCard>

      <PanelCard title="运行状态">
        <div class="dl">
          <div class="dl-row">
            <span class="dl-key">XDP 挂载</span>
            <span class="state" :class="xdpMode === 'native' ? 'ok' : 'warn'">
              <span class="dot" :class="xdpMode === 'native' ? 'ok' : 'warn'"></span>
              {{ xdpMode === 'generic' ? 'generic（SKB）' : xdpMode }}
            </span>
          </div>
          <div class="dl-row">
            <span class="dl-key">挂载状态</span>
            <span class="state" :class="s && (s as never as Record<string, unknown>).xdp_attached === false ? 'danger' : 'ok'">
              <span class="dot" :class="s && (s as never as Record<string, unknown>).xdp_attached === false ? 'danger' : 'ok'"></span>
              {{ !s || (s as never as Record<string, unknown>).xdp_attached === undefined ? '—' : (s as never as Record<string, unknown>).xdp_attached === false ? '未挂载' : '已挂载 · 15s 校验' }}
            </span>
          </div>
          <div class="dl-row"><span class="dl-key">版本</span><span class="dl-val">v{{ cfg?.version || '—' }}</span></div>
          <div class="dl-row"><span class="dl-key">网卡</span><span class="dl-val">{{ cfg?.interface || '—' }}</span></div>
          <div class="dl-row"><span class="dl-key">监听地址</span><span class="dl-val">{{ cfg?.web_bind || '—' }}</span></div>
          <div class="dl-row">
            <span class="dl-key">Hub 连接</span>
            <span class="state" :class="hub.connected ? 'ok' : 'warn'">
              <span class="dot" :class="hub.connected ? 'ok' : 'warn'"></span>
              {{ hub.connected ? '已连接' : '未连接' }}
            </span>
          </div>
          <div class="dl-row"><span class="dl-key">存储路径</span><span class="dl-val" :title="cfg?.store_path">{{ cfg?.store_path || '—' }}</span></div>
        </div>
      </PanelCard>
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="TOP 攻击源" sub="按累计命中次数" flush>
        <template #actions>
          <button class="btn btn-ghost btn-sm" @click="router.push('/attacks')">全部事件</button>
        </template>
        <div class="table-wrap">
          <table class="dt">
            <thead>
              <tr><th style="width: 32px">#</th><th>源地址</th><th class="col-num">命中次数</th><th style="width: 140px">占比</th><th>动作</th><th class="col-actions">操作</th></tr>
            </thead>
            <tbody>
              <tr v-for="(a, i) in (s?.top_attackers || []).slice(0, 8)" :key="a.ip">
                <td class="muted mono">{{ i + 1 }}</td>
                <td>
                  <span class="mono cell-link" @click="openDrawer('IP 详情', 'ip', { ip: a.ip, count: a.count })">{{ a.ip }}</span>
                </td>
                <td class="col-num mono">{{ fmtInt(a.count) }}</td>
                <td>
                  <span class="hbar-track"><span class="hbar-fill danger" :style="{ width: ((a.count / (s?.top_attackers?.[0]?.count || 1)) * 100) + '%' }"></span></span>
                </td>
                <td><span class="state danger"><span class="dot danger"></span>DROP</span></td>
                <td class="col-actions">
                  <div class="row-actions"><button class="btn btn-sm" @click="openDrawer('IP 详情', 'ip', { ip: a.ip, count: a.count })">详情</button></div>
                </td>
              </tr>
              <tr v-if="!s?.top_attackers?.length"><td colspan="6" class="empty"><div class="title">暂无攻击源</div>数据面尚未上报命中</td></tr>
            </tbody>
          </table>
        </div>
      </PanelCard>

      <div class="grid" style="gap: 14px; grid-template-columns: minmax(0, 1fr)">
        <PanelCard title="拦截原因分布" sub="累计">
          <BarList :items="reasons" :format="(v: number) => { const c = fmtCompact(v); return c.value + c.unit }" />
        </PanelCard>
        <PanelCard title="防护模块" :sub="`${enabledModules} / ${modules.length} 启用`">
          <div class="dl" style="margin-top: -6px">
            <div v-for="m in modules.slice(0, 7)" :key="m.id" class="dl-row">
              <span class="dl-key">
                {{ m.name }}
                <span v-if="m.id === 'syn_flood'" class="muted">· 实验</span>
              </span>
              <span class="row" style="gap: 8px">
                <span class="mono muted" style="font-size: 11px">{{ moduleStat(m) }}</span>
                <ToggleSwitch :model-value="m.enabled" @update:model-value="(v: boolean) => toggleModule(m, v)" />
              </span>
            </div>
          </div>
        </PanelCard>
      </div>
    </div>

    <div class="grid grid-2">
      <PanelCard title="防护有效性" sub="累计口径 · 覆盖 11 个拦截模块">
        <template #actions>
          <span class="tag" :title="blockModeHint">限速处置 <span class="mono">{{ blockMode }}</span></span>
        </template>
        <div class="eff-summary">
          <div>
            <div class="muted" style="font-size: 11px">累计丢弃率</div>
            <div class="eff-value" :class="dropTone">{{ fmtPercent(lifetimeDropRate) }}</div>
          </div>
          <div class="eff-side">
            <span class="state">已丢弃 <span class="mono">{{ fmtInt(s?.total_dropped || 0) }}</span></span>
            <span class="state">已处理 <span class="mono">{{ fmtInt(s?.total_packets || 0) }}</span></span>
          </div>
        </div>
        <div class="progress" :class="dropTone" style="margin: 9px 0 12px">
          <i :style="{ width: dropProgress + '%' }"></i>
        </div>
        <div class="muted" style="font-size: 11px; margin-bottom: 8px">各模块拦截占比（累计）</div>
        <BarList
          class="wide-label"
          :items="effectiveness"
          :format="(v: number) => { const c = fmtCompact(v); return c.value + c.unit }"
        />
        <div class="muted" style="font-size: 11px; margin-top: 10px; padding-top: 9px; border-top: 1px solid var(--border); line-height: 1.55">
          「端口聚合限速」按 协议 + 目的端口 维度统计，防伪造源 IP 绕过单源限速；「分片策略」仅作用于非首片 IPv4 分片。
        </div>
      </PanelCard>

      <PanelCard
        title="表项水位"
        :sub="`使用率 ≥ ${fmtPercent(mapUsage?.warn_threshold ?? 0.8, 0)} 触发告警`"
        flush
        body-style="display: flex; flex-direction: column; flex: 1 1 auto; min-height: 0"
      >
        <template #actions>
          <span
            class="muted"
            style="font-size: 11px"
            title="服务端每 30s 采样一次 map 条目数（CLOCK_MONOTONIC 单调时钟），这里展示控制台估算的最近采样时间"
          >
            最近采样 <span class="mono">{{ mapSampledAt ? fmtAgo(mapSampledAt * 1e6) : '—' }}</span>
          </span>
        </template>
        <div class="mu-list">
          <div v-for="m in mapRows" :key="m.name" class="mu-row">
            <span class="mu-name mono" :title="`${m.name} · ${m.type || 'map'}`">{{ m.name }}</span>
            <span class="hbar-track">
              <span class="hbar-fill" :class="mapRatioTone(m)" :style="{ width: Math.max(2, Math.min(100, m.ratio * 100)) + '%' }"></span>
            </span>
            <span class="mu-val mono">{{ fmtCap(m.entries) }} / {{ fmtCap(m.max, true) }}</span>
            <span class="mu-pct mono" :class="mapRatioTone(m)">{{ fmtPercent(m.ratio, 1) }}</span>
          </div>
          <div v-if="!mapRows.length" class="empty"><div class="title">暂无水位数据</div>等待服务端完成首次 map 采样</div>
        </div>
        <div class="mu-foot">{{ mapTotal ? `共 ${mapTotal} 张表 · 按使用率降序 · 服务端每 30s 采样` : '等待采样' }}</div>
      </PanelCard>
    </div>

    <PanelCard title="最近攻击事件" sub="RingBuf 采样 · 最多 200 条" flush>
      <template #actions>
        <span class="state"><span class="dot live"></span>实时</span>
      </template>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>时间</th><th>源地址</th><th>目的</th><th>协议</th><th>命中规则</th><th>动作</th><th class="col-actions">操作</th></tr></thead>
          <tbody>
            <tr v-for="e in events" :key="e.id">
              <td class="mono muted">{{ fmtTime(e.timestamp_ns) }}</td>
              <td>
                <span class="mono cell-link" @click="openDrawer('IP 详情', 'ip', { ip: e.src_ip, count: 0 })">{{ e.src_ip }}</span>
              </td>
              <td class="mono">{{ e.dst_ip }}:{{ e.dst_port }}</td>
              <td class="muted">{{ e.protocol }}</td>
              <td>{{ e.reason }}</td>
              <td>
                <span class="state" :class="e.action === 'DROP' ? 'danger' : 'ok'">
                  <span class="dot" :class="e.action === 'DROP' ? 'danger' : 'ok'"></span>{{ e.action }}
                </span>
              </td>
              <td class="col-actions">
                <div class="row-actions"><button class="btn btn-sm" @click="openDrawer('事件详情', 'event', e)">详情</button></div>
              </td>
            </tr>
            <tr v-if="!events.length"><td colspan="7" class="empty">暂无事件</td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>
  </div>
</template>
