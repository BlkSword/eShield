<script setup lang="ts">
import { computed } from 'vue'
import Sparkline from './Sparkline.vue'
import { fmtCompact } from '../utils/format'

const props = defineProps<{
  label: string
  value: number
  unit?: string
  kind?: 'accent' | 'ok' | 'warn' | 'danger' | 'violet'
  delta?: string
  deltaKind?: 'up' | 'down' | 'flat'
  foot?: string
  spark?: number[]
  raw?: string
}>()
const display = computed(() => {
  if (props.raw) return props.raw
  const { value, unit } = fmtCompact(props.value)
  return value + (props.unit || unit)
})
const color = computed(() => {
  const map: Record<string, string> = {
    accent: 'var(--accent)', ok: 'var(--ok)', warn: 'var(--warn)', danger: 'var(--danger)', violet: 'var(--violet)',
  }
  return map[props.kind || 'accent']
})
</script>
<template>
  <div class="kpi" :class="props.kind || 'accent'">
    <div class="k-label">{{ props.label }}</div>
    <div class="k-value">{{ display }}</div>
    <div class="k-foot">
      <span v-if="props.delta" :style="{ color: props.deltaKind === 'up' ? 'var(--ok)' : props.deltaKind === 'down' ? 'var(--danger)' : 'var(--text-3)' }">
        {{ props.deltaKind === 'up' ? '▲' : props.deltaKind === 'down' ? '▼' : '·' }} {{ props.delta }}
      </span>
      <span v-else>{{ props.foot }}</span>
      <span v-if="props.foot && props.delta">{{ props.foot }}</span>
    </div>
    <div v-if="props.spark" class="spark"><Sparkline :data="props.spark" :color="color" /></div>
  </div>
</template>
