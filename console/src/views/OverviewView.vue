<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRouter } from 'vue-router'
import LineChart from '../components/LineChart.vue'
import BarList from '../components/BarList.vue'
import KpiCard from '../components/KpiCard.vue'
import PanelCard from '../components/PanelCard.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api } from '../api/client'
import { store, toast } from '../stores/app'
import type { AttackEvent, ConfigSnapshot, ModuleState } from '../api/types'
import { fmtCompact, fmtInt, fmtPercent, fmtRate, fmtTime } from '../utils/format'
import { openDrawer } from '../stores/ui'

const router = useRouter()
const modules = ref<ModuleState[]>([])
const events = ref<AttackEvent[]>([])
const cfg = ref<ConfigSnapshot | null>(null)
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
}

onMounted(loadMeta)

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
