<script setup lang="ts">
import { computed } from 'vue'
import { fmtCompact } from '../utils/format'

interface Series { name: string; color: string; data: number[] }
const props = defineProps<{ series: Series[]; labels: string[]; height?: number }>()

const W = 1000
const PAD = 4
const H = computed(() => props.height ?? 200)
const count = computed(() => Math.max(2, props.series[0]?.data.length || 2))

const peak = computed(() => {
  let max = 0
  for (const s of props.series) for (const v of s.data) if (v > max) max = v
  return max
})
const max = computed(() => {
  if (peak.value <= 0) return 1
  const mag = Math.pow(10, Math.floor(Math.log10(peak.value)))
  const step = Math.ceil(peak.value / mag / 4) * mag
  return step * 4
})
const yTicks = computed(() => [max.value, max.value * 0.75, max.value * 0.5, max.value * 0.25, 0])

const x = (i: number) => PAD + (i / (count.value - 1)) * (W - PAD * 2)
const y = (v: number) => H.value - PAD - (v / max.value) * (H.value - PAD * 2)

function line(data: number[]) {
  const n = Math.max(1, data.length - 1)
  return data
    .map((v, i) => `${i ? 'L' : 'M'}${(PAD + (i / n) * (W - PAD * 2)).toFixed(1)},${y(v).toFixed(1)}`)
    .join('')
}
function area(data: number[]) {
  return `${line(data)}L${W - PAD},${H.value - PAD}L${PAD},${H.value - PAD}Z`
}

/* 悬停十字线 + 数值气泡 */
const hover = defineModel<number | null>('hover', { default: null })
function onMove(e: MouseEvent) {
  const rect = (e.currentTarget as HTMLElement).getBoundingClientRect()
  const rel = Math.min(1, Math.max(0, (e.clientX - rect.left) / rect.width))
  hover.value = Math.round(rel * (count.value - 1))
}
const hoverX = computed(() => (hover.value == null ? 0 : x(hover.value)))
const tipStyle = computed(() => {
  const pct = hover.value == null ? 0 : (hover.value / (count.value - 1)) * 100
  return { left: `clamp(8px, ${pct}%, calc(100% - 150px))` }
})
const hoverLabel = computed(() => {
  if (hover.value == null) return ''
  const n = Math.max(1, props.labels.length - 1)
  const i = Math.round((hover.value / (count.value - 1)) * n)
  return props.labels[Math.min(n, i)] || ''
})
</script>

<template>
  <div class="chart-wrap" @mousemove="onMove" @mouseleave="hover = null">
    <div class="chart-ylabels">
      <span v-for="(t, i) in yTicks" :key="i">{{ fmtCompact(t).value }}{{ fmtCompact(t).unit }}</span>
    </div>
    <svg class="chart" :viewBox="`0 0 ${W} ${H}`" :style="{ height: H + 'px' }" preserveAspectRatio="none">
      <g v-for="(t, i) in yTicks" :key="'g' + i">
        <line
          x1="0" :x2="W" :y1="y(t)" :y2="y(t)"
          stroke="var(--grid-line)" stroke-width="1" vector-effect="non-scaling-stroke"
        />
      </g>
      <path v-for="s in props.series" :key="'a' + s.name" :d="area(s.data)" :fill="s.color" opacity="0.06" />
      <path
        v-for="s in props.series" :key="'l' + s.name"
        :d="line(s.data)" fill="none" :stroke="s.color"
        stroke-width="1.5" vector-effect="non-scaling-stroke" stroke-linejoin="round"
      />
      <line
        v-if="hover != null"
        :x1="hoverX" :x2="hoverX" y1="0" :y2="H"
        stroke="var(--border-strong)" stroke-width="1" stroke-dasharray="3 3"
        vector-effect="non-scaling-stroke"
      />
    </svg>
    <div class="chart-xlabels">
      <span v-for="(l, i) in props.labels" :key="i">{{ l }}</span>
    </div>
    <div v-if="hover != null" class="chart-tip" :style="tipStyle">
      <div class="muted" style="margin-bottom: 3px">{{ hoverLabel }}</div>
      <div v-for="s in props.series" :key="'t' + s.name" class="tt-row">
        <i :style="{ background: s.color }"></i>
        <span class="muted">{{ s.name }}</span>
        <span class="mono" style="margin-left: auto">{{ (s.data[hover] ?? 0).toLocaleString() }}</span>
      </div>
    </div>
  </div>
</template>
