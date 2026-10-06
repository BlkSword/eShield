<script setup lang="ts">
import * as echarts from 'echarts'
import { onBeforeUnmount, onMounted, ref, watch } from 'vue'

const props = defineProps<{ option: any; height?: string }>()
const el = ref<HTMLDivElement | null>(null)
let chart: echarts.ECharts | null = null
let ro: ResizeObserver | null = null

function cssVar(name: string, fallback: string) {
  const v = getComputedStyle(document.documentElement).getPropertyValue(name).trim()
  return v || fallback
}

function themed(option: any): any {
  const text = cssVar('--text-2', '#475467')
  const border = cssVar('--border', '#e3e7ee')
  const surface = cssVar('--surface', '#fff')
  return {
    textStyle: { fontFamily: cssVar('--font-sans', 'sans-serif'), color: text },
    grid: { left: 8, right: 12, top: 24, bottom: 4, containLabel: true, ...(option.grid as object) },
    tooltip: {
      trigger: 'axis',
      backgroundColor: surface,
      borderColor: border,
      borderWidth: 1,
      padding: [8, 10],
      textStyle: { color: cssVar('--text', '#101828'), fontSize: 12 },
      axisPointer: { lineStyle: { color: border } },
      ...(option.tooltip as object),
    },
    ...option,
  }
}

function render() {
  if (!chart) return
  chart.setOption(themed(props.option), true)
}
onMounted(() => {
  if (!el.value) return
  chart = echarts.init(el.value, undefined, { renderer: 'canvas' })
  render()
  ro = new ResizeObserver(() => chart?.resize())
  ro.observe(el.value)
  window.addEventListener('eshield:theme', render)
})
watch(() => props.option, render, { deep: true })
onBeforeUnmount(() => {
  ro?.disconnect()
  window.removeEventListener('eshield:theme', render)
  chart?.dispose()
})
</script>

<template>
  <div ref="el" class="chart" :style="{ height: props.height || '220px' }"></div>
</template>
