<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { navGroups } from '../router'
import { store } from '../stores/app'
import { fmtCompact } from '../utils/format'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ (e: 'navigate'): void }>()
const route = useRoute()
const active = computed(() => route.path)

const xdp = computed(() => {
  const s = store.stats as Record<string, unknown> | null
  if (!s) return { text: '连接中', dot: 'warn' }
  if (s.xdp_attached === false) return { text: 'XDP 未挂载', dot: 'danger' }
  const mode = String(s.xdp_mode || 'unknown')
  return { text: `XDP ${mode === 'native' ? 'native' : mode === 'generic' ? 'SKB' : mode}`, dot: mode === 'native' ? 'ok' : 'warn' }
})
const attackBadge = computed(() => {
  const dps = store.stats?.current_dps || 0
  if (!dps) return ''
  const c = fmtCompact(dps)
  return c.value + c.unit
})
</script>

<template>
  <aside class="sidebar" :class="{ open: props.open }">
    <div class="brand">
      <div class="brand-mark" aria-hidden="true">
        <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round">
          <path d="M12 3 4.5 6v5.5c0 4.2 3.1 7.6 7.5 9.5 4.4-1.9 7.5-5.3 7.5-9.5V6L12 3Z" />
          <path d="M8.8 12.1l2.1 2.1 4.3-4.4" stroke-linecap="round" />
        </svg>
      </div>
      <div class="brand-name">eShield</div>
      <div class="brand-ver">0.4.8</div>
    </div>
    <div class="side-scroll">
      <div v-for="g in navGroups" :key="g.label" class="nav-group">
        <div class="nav-group-label">{{ g.label }}</div>
        <router-link
          v-for="item in g.items"
          :key="item.path"
          :to="item.path"
          class="nav-item"
          :class="{ active: active === item.path }"
          @click="emit('navigate')"
        >
          <span>{{ item.label }}</span>
          <span v-if="item.path === '/attacks' && attackBadge" class="nav-badge">{{ attackBadge }}</span>
        </router-link>
      </div>
    </div>
    <div class="side-foot">
      <div class="state">
        <span class="dot" :class="xdp.dot"></span>
        <span>{{ xdp.text }}</span>
      </div>
    </div>
  </aside>
</template>
