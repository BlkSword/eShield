<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { cycleTheme, live, refresh, store, openSearch } from '../stores/app'
import { fmtRate } from '../utils/format'

const emit = defineEmits<{ (e: 'toggle-sidebar'): void }>()
const route = useRoute()
const title = computed(() => (route.meta.title as string) || 'eShield')
const sub = computed(() => (route.meta.sub as string) || '')
const dangerLabel = computed(() => {
  const d = store.stats?.danger_level ?? 0
  return ['L0 平稳', 'L1 关注', 'L2 警戒', 'L3 严重'][Math.min(d, 3)]
})
const dangerClass = computed(() => ['tag-ok', 'tag-info', 'tag-warn', 'tag-danger'][Math.min(store.stats?.danger_level ?? 0, 3)])
const themeLabel = computed(() => (store.theme === 'system' ? '跟随系统' : store.theme === 'light' ? '浅色' : '深色'))
</script>

<template>
  <header class="topbar">
    <button class="icon-btn" style="display: none" @click="emit('toggle-sidebar')">☰</button>
    <div class="crumb">
      <span class="title">{{ title }}</span>
      <span class="sub">{{ sub }}</span>
    </div>
    <div class="spacer"></div>
    <div class="topbar-actions">
      <div class="search" @click="openSearch()">
        <input readonly placeholder="搜索 IP、规则、页面…" />
        <kbd>Ctrl K</kbd>
      </div>
      <span class="tag" :class="live ? 'tag-ok' : 'tag-warn'">
        <span class="dot" :class="{ pulse: live }"></span>{{ live ? '实时' : '演示数据' }}
      </span>
      <span class="tag tag-danger" v-if="store.stats">
        攻击 {{ fmtRate(store.stats.current_dps) }}
      </span>
      <span class="tag" :class="dangerClass">{{ dangerLabel }}</span>
      <span class="tag tag-info" v-if="store.stats">PPS {{ fmtRate(store.stats.current_pps) }}</span>
      <button class="icon-btn" :title="`当前 ${themeLabel}`" @click="refresh(true)">刷新</button>
      <button class="icon-btn" :title="`主题：${themeLabel}`" @click="cycleTheme()">主题</button>
      <div class="avatar" title="admin">AD</div>
    </div>
  </header>
</template>
