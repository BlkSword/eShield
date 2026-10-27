<script setup lang="ts">
import { computed } from 'vue'

export interface BarItem { label: string; value: number; tone?: 'accent' | 'danger' | 'warn' | 'ok' | 'violet' | 'muted' }

const props = defineProps<{ items: BarItem[]; format?: (v: number) => string }>()
const max = computed(() => Math.max(1, ...props.items.map((i) => i.value)))
const fmt = (v: number) => (props.format ? props.format(v) : v.toLocaleString())
</script>

<template>
  <div class="hbars">
    <div v-for="b in props.items" :key="b.label" class="hbar">
      <span class="hbar-label" :title="b.label">{{ b.label }}</span>
      <span class="hbar-track">
        <span class="hbar-fill" :class="b.tone && b.tone !== 'muted' ? b.tone : ''" :style="{ width: Math.max(2, (b.value / max) * 100) + '%' }"></span>
      </span>
      <span class="hbar-val">{{ fmt(b.value) }}</span>
    </div>
    <div v-if="!props.items.length" class="muted" style="font-size: 11.5px">暂无数据</div>
  </div>
</template>
