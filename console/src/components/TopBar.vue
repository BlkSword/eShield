<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { cycleTheme, isReadonly, live, refresh, store, openSearch, logout } from '../stores/app'
import { navGroups } from '../router'

const emit = defineEmits<{ (e: 'toggle-sidebar'): void }>()
const route = useRoute()

const groupLabel = computed(() => navGroups.find((g) => g.items.some((i) => i.path === route.path))?.label || '控制台')
const title = computed(() => (route.meta.title as string) || 'eShield')

const xdp = computed(() => {
  const s = store.stats as Record<string, unknown> | null
  if (!s) return { text: '连接中', dot: 'warn', title: '正在连接数据面' }
  if (s.xdp_attached === false) return { text: 'XDP 未挂载', dot: 'danger', title: 'XDP 程序未挂载，防护已失效' }
  const mode = String(s.xdp_mode || '')
  return {
    text: mode === 'native' ? 'XDP native' : mode === 'generic' ? 'XDP generic' : 'XDP —',
    dot: mode === 'native' ? 'ok' : 'warn',
    title: mode === 'native' ? 'XDP 运行在原生驱动模式' : 'XDP 运行在 generic/SKB 模式（性能低于 native）',
  }
})
const themeLabel = computed(() => (store.theme === 'system' ? '跟随系统' : store.theme === 'light' ? '浅色' : '深色'))
const online = computed(() => !!store.stats)

async function onLogout() {
  await logout()
}
</script>

<template>
  <header class="topbar">
    <button class="icon-btn" style="display: none" @click="emit('toggle-sidebar')">菜单</button>
    <div class="crumb">
      <span class="crumb-group">{{ groupLabel }}</span>
      <span class="crumb-sep">/</span>
      <span class="crumb-title">{{ title }}</span>
    </div>
    <div class="spacer"></div>
    <div class="search" role="search" @click="openSearch()">
      <span>⌕</span>
      <span>搜索 IP、规则、事件…</span>
      <kbd>Ctrl K</kbd>
    </div>
    <span class="state" :title="xdp.title"><span class="dot" :class="xdp.dot"></span>{{ xdp.text }}</span>
    <span v-if="isReadonly" class="state warn" title="只读令牌：可查看全部数据，写操作会被服务端拒绝（403）">
      <span class="dot warn"></span>只读
    </span>
    <span class="state"><span class="dot" :class="live ? 'live' : 'warn'"></span>{{ live ? '实时' : '演示数据' }}</span>
    <span class="topbar-divider"></span>
    <button class="icon-btn" toggles="refresh" title="刷新（R）" @click="refresh(true)">刷新</button>
    <button class="icon-btn" title="切换主题" @click="cycleTheme()">{{ themeLabel }}</button>
    <button v-if="online" class="icon-btn" title="退出登录" @click="onLogout()">退出</button>
  </header>
</template>
