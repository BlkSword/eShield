<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import EChart from '../components/EChart.vue'
import KpiCard from '../components/KpiCard.vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { store } from '../stores/app'
import { api, state } from '../api/client'
import type { AttackEvent, ModuleState } from '../api/types'
import { fmtCompact, fmtInt, fmtPercent, fmtRate, fmtTime } from '../utils/format'
import { openDrawer } from '../stores/ui'

const modules = ref<ModuleState[]>([])
const events = ref<AttackEvent[]>([])
const loading = ref(true)

const s = computed(() => store.stats)
const dropRate = computed(() => (s.value && s.value.current_pps ? s.value.current_dps / s.value.current_pps : 0))
const ppsSpark = computed(() => store.series.map((p) => p.pps))
const dropSpark = computed(() => store.series.map((p) => p.dps))

const trafficOption = computed(() => ({
  color: ['#2f6bff', '#e5484d'],
  legend: { show: true, top: 0, right: 0, itemWidth: 10, itemHeight: 10, textStyle: { fontSize: 11 } },
  grid: { left: 8, right: 14, top: 34, bottom: 6, containLabel: true },
  xAxis: {
    type: 'category',
    boundaryGap: false,
    data: store.series.map((p) => fmtTime(new Date(p.t).getTime() * 1e6)),
    axisLine: { lineStyle: { color: 'var(--border)' } },
    axisTick: { show: false },
    axisLabel: { fontSize: 11, color: 'var(--text-3)' },
  },
  yAxis: {
    type: 'value',
    splitLine: { lineStyle: { color: 'var(--border)' } },
    axisLabel: { fontSize: 11, color: 'var(--text-3)', formatter: (v: number) => fmtCompact(v).value + fmtCompact(v).unit },
  },
  series: [
    { name: 'PPS', type: 'line', smooth: true, showSymbol: false, lineStyle: { width: 2 }, areaStyle: { opacity: 0.12 }, data: store.series.map((p) => p.pps) },
    { name: 'DROP', type: 'line', smooth: true, showSymbol: false, lineStyle: { width: 2 }, areaStyle: { opacity: 0.14 }, data: store.series.map((p) => p.dps) },
  ],
}))

const reasonOption = computed(() => {
  const v = s.value
  if (!v) return {}
  const data = [
    { name: '黑名单', value: v.blacklist_blocked, itemStyle: { color: '#e5484d' } },
    { name: '速率限制', value: v.rate_limited, itemStyle: { color: '#f0a63a' } },
    { name: 'SYN Flood', value: v.syn_flood_blocked, itemStyle: { color: '#7c5cff' } },
    { name: 'GeoIP', value: v.geoip_blocked, itemStyle: { color: '#0ea5e9' } },
    { name: '连接跟踪', value: v.conn_track_blocked, itemStyle: { color: '#12a150' } },
    { name: 'L7', value: v.l7_blocked, itemStyle: { color: '#2f6bff' } },
  ].filter((d) => d.value > 0)
  return {
    tooltip: { trigger: 'item', formatter: '{b}: {c} ({d}%)' },
    legend: { bottom: 0, icon: 'circle', itemWidth: 8, itemHeight: 8, textStyle: { fontSize: 11 } },
    series: [{
      type: 'pie', radius: ['52%', '74%'], center: ['50%', '44%'], avoidLabelOverlap: true,
      itemStyle: { borderColor: 'var(--surface)', borderWidth: 2 },
      label: { show: false }, data,
    }],
  }
})

onMounted(async () => {
  const [mods, evs] = await Promise.all([api.modules(s.value as any), api.attackEvents()])
  modules.value = mods
  events.value = evs.slice(0, 9)
  loading.value = false
})

function toggleModule(m: ModuleState, v: boolean) {
  m.enabled = v
}
</script>

<template>
  <div class="page">
    <div class="kpi-grid">
      <KpiCard label="当前 PPS" :value="s?.current_pps || 0" kind="accent" :delta="`峰值 ${fmtRate(Math.max(...ppsSpark))}`" delta-kind="flat" :spark="ppsSpark" />
      <KpiCard label="当前 DROP" :value="s?.current_dps || 0" kind="danger" :delta="`丢弃率 ${fmtPercent(dropRate)}`" delta-kind="down" :spark="dropSpark" />
      <KpiCard label="累计处理包" :value="s?.total_packets || 0" kind="violet" :foot="`放行 ${fmtCompact(s?.total_passed || 0).value}${fmtCompact(s?.total_passed || 0).unit}`" />
      <KpiCard label="累计拦截" :value="s?.total_dropped || 0" kind="warn" :foot="`黑名单 ${fmtCompact(s?.blacklist_blocked || 0).value}${fmtCompact(s?.blacklist_blocked || 0).unit}`" />
      <KpiCard label="恶意源" :value="s?.trust_malicious || 0" kind="danger" :foot="`可疑 ${fmtInt(s?.trust_suspicious)}`" />
      <KpiCard label="危险等级" :value="s?.danger_level || 0" kind="warn" :raw="'L' + (s?.danger_level || 0)" :foot="['平稳', '关注', '警戒', '严重'][Math.min(s?.danger_level || 0, 3)]" />
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="流量趋势" sub="近 24 小时 · 30 分钟粒度">
        <template #actions><TagPill text="PPS / DROP" kind="tag-info" /></template>
        <EChart :option="trafficOption" height="286px" />
      </PanelCard>
      <PanelCard title="拦截原因分布" sub="累计 DROP 计数">
        <EChart :option="reasonOption" height="286px" />
      </PanelCard>
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="TOP 攻击源" sub="按累计命中次数" flush>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th style="width: 34px">#</th><th>源地址</th><th class="col-num">命中次数</th><th style="width: 160px">占比</th><th></th></tr></thead>
            <tbody>
              <tr v-for="(a, i) in (s?.top_attackers || []).slice(0, 7)" :key="a.ip">
                <td class="muted">{{ i + 1 }}</td>
                <td><span class="mono cell-main" style="cursor: pointer" @click="openDrawer('IP 详情', 'ip', a)">{{ a.ip }}</span></td>
                <td class="col-num mono">{{ fmtInt(a.count) }}</td>
                <td>
                  <div class="progress danger"><i :style="{ width: `${(a.count / (s?.top_attackers?.[0]?.count || 1)) * 100}%` }"></i></div>
                </td>
                <td class="col-actions"><TagPill text="DROP" kind="tag-danger" /></td>
              </tr>
            </tbody>
          </table>
        </div>
      </PanelCard>

      <div class="grid" style="gap: 14px">
        <PanelCard title="防护模块" sub="数据面实时生效">
          <template #actions><TagPill :text="`${modules.filter((m) => m.enabled).length}/${modules.length} 启用`" kind="tag-accent" /></template>
          <div class="col" style="gap: 2px">
            <div v-for="m in modules.slice(0, 7)" :key="m.id" class="spread" style="padding: 7px 0; border-bottom: 1px solid var(--border)">
              <div class="col" style="gap: 1px; min-width: 0">
                <span class="strong" style="font-size: 12.5px">{{ m.name }}</span>
                <span class="muted" style="font-size: 11px">{{ m.group }}</span>
              </div>
              <div class="row">
                <span v-if="m.statsKey && s" class="mono muted" style="font-size: 11.5px">{{ fmtCompact(s[m.statsKey] as number).value }}{{ fmtCompact(s[m.statsKey] as number).unit }}</span>
                <ToggleSwitch v-model="m.enabled" @update:model-value="(v: boolean) => toggleModule(m, v)" />
              </div>
            </div>
          </div>
        </PanelCard>
      </div>
    </div>

    <PanelCard title="最近攻击事件" sub="RingBuf 采样，最多保留最近 200 条" flush>
      <template #actions>
        <TagPill :text="state.live ? '实时' : '演示数据'" :kind="state.live ? 'tag-ok' : 'tag-warn'" dot />
      </template>
      <div class="table-wrap">
        <table class="dt">
          <thead>
            <tr><th>时间</th><th>源地址</th><th>目的</th><th>协议</th><th>命中规则</th><th>动作</th><th></th></tr>
          </thead>
          <tbody>
            <tr v-for="e in events" :key="e.id">
              <td class="mono muted nowrap">{{ fmtTime(e.timestamp_ns) }}</td>
              <td><span class="mono cell-main" style="cursor: pointer" @click="openDrawer('IP 详情', 'ip', { ip: e.src_ip, count: 0 })">{{ e.src_ip }}</span></td>
              <td class="mono">{{ e.dst_ip }}:{{ e.dst_port }}</td>
              <td><TagPill :text="e.protocol" :kind="e.protocol === 'TCP' ? 'tag-info' : e.protocol === 'UDP' ? 'tag-violet' : 'tag-warn'" /></td>
              <td>{{ e.reason }}</td>
              <td><TagPill :text="e.action" :kind="e.action === 'DROP' ? 'tag-danger' : 'tag-ok'" /></td>
              <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="openDrawer('事件详情', 'event', e)">详情</button></td>
        
              </tr>
              <tr v-if="!events.length"><td colspan="7" class="empty">暂无事件</td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>
  </div>
</template>
