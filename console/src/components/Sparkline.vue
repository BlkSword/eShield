<script setup lang="ts">
import { computed } from 'vue'
const props = defineProps<{ data: number[]; color?: string; fill?: boolean }>()
const w = 86, h = 16
const path = computed(() => {
  const d = props.data.length ? props.data : [0, 0]
  const min = Math.min(...d), max = Math.max(...d)
  const span = max - min || 1
  return d.map((v, i) => {
    const x = (i / (d.length - 1)) * w
    const y = h - 2 - ((v - min) / span) * (h - 4)
    return `${i ? 'L' : 'M'}${x.toFixed(2)},${y.toFixed(2)}`
  }).join(' ')
})
const area = computed(() => `${path.value} L${w},${h} L0,${h} Z`)
</script>
<template>
  <svg :viewBox="`0 0 ${w} ${h}`" preserveAspectRatio="none" class="spark">
    <path v-if="props.fill !== false" :d="area" :fill="props.color || 'var(--accent)'" opacity="0.08" />
    <path :d="path" fill="none" :stroke="props.color || 'var(--accent)'" stroke-width="1.2"
      vector-effect="non-scaling-stroke" stroke-linejoin="round" stroke-linecap="round" />
  </svg>
</template>
