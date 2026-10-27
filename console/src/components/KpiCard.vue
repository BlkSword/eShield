<script setup lang="ts">
import { computed } from 'vue'
import Sparkline from './Sparkline.vue'
import { fmtCompact, fmtInt } from '../utils/format'

const props = defineProps<{
  label: string
  value: number | string
  /** 数值格式：compact（默认，1.2M）/ int（千分位）/ raw */
  format?: 'compact' | 'int' | 'raw'
  unit?: string
  foot?: string
  tone?: 'default' | 'ok' | 'warn' | 'danger' | 'accent'
  spark?: number[]
  sparkColor?: string
}>()

const display = computed(() => {
  if (typeof props.value === 'string') return props.value
  const f = props.format || 'compact'
  if (f === 'raw') return String(props.value)
  if (f === 'int') return fmtInt(props.value)
  const { value, unit } = fmtCompact(props.value)
  return value + (props.unit || unit)
})
const color = computed(() => {
  const map: Record<string, string> = {
    default: 'var(--text-3)', ok: 'var(--ok)', warn: 'var(--warn)',
    danger: 'var(--danger)', accent: 'var(--accent)',
  }
  return map[props.tone || 'default']
})
</script>
<template>
  <div class="kpi">
    <div class="k-label">
      <span>{{ props.label }}</span>
      <span v-if="props.tone && props.tone !== 'default'" class="dot" :class="props.tone"></span>
    </div>
    <div class="k-value">{{ display }}</div>
    <div class="k-foot">
      <Sparkline v-if="props.spark && props.spark.length > 1" :data="props.spark" :color="props.sparkColor || color" class="spark" />
      <span v-if="props.foot">{{ props.foot }}</span>
    </div>
  </div>
</template>
