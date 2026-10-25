import { reactive, ref } from 'vue'
import { api, getToken, setToken } from '../api/client'
import type { SeriesPoint, Stats } from '../api/types'

export const polls = ref(0)
export const live = ref(false)
export const danger = ref(0)

export const store = reactive({
  stats: null as Stats | null,
  series: [] as SeriesPoint[],
  loading: true,
  lastUpdated: 0,
  autoRefresh: true,
  theme: localStorage.getItem('eshield-theme') || 'system',
})

export const toasts = reactive<{ id: number; kind: string; title: string; desc?: string }[]>([])
let toastSeq = 0
export function toast(title: string, desc = '', kind: 'ok' | 'warn' | 'danger' | 'info' = 'ok') {
  const id = ++toastSeq
  toasts.push({ id, kind, title, desc })
  setTimeout(() => {
    const i = toasts.findIndex((t) => t.id === id)
    if (i >= 0) toasts.splice(i, 1)
  }, 3600)
}

export async function refresh(force = false) {
  if (!store.autoRefresh && !force) return
  try {
    const [stats, series] = await Promise.all([api.stats(), api.series()])
    store.stats = stats
    store.series = series
    store.lastUpdated = Date.now()
    live.value = api.isLive()
    danger.value = stats.danger_level
    polls.value++
  } catch (e) {
    // keep last known values; surface only when the user forced a refresh
    if (force) toast('刷新失败', String(e), 'danger')
  } finally {
    store.loading = false
  }
}

export function initTheme() {
  const apply = () => {
    const t = store.theme
    document.documentElement.dataset.theme = t
  }
  apply()
}
export function cycleTheme() {
  store.theme = store.theme === 'system' ? 'light' : store.theme === 'light' ? 'dark' : 'system'
  localStorage.setItem('eshield-theme', store.theme)
  initTheme()
}

export const commandOpen = ref(false)
export const searchSeed = ref('')
export function openSearch(seed = '') {
  searchSeed.value = seed
  commandOpen.value = true
}

export async function logout() {
  setToken('')
  // 清掉后端下发的 HttpOnly 会话 Cookie，否则刷新页面仍会被自动认证。
  try {
    await fetch('/api/auth/logout', { method: 'POST', credentials: 'same-origin' })
  } catch { /* 离线/演示模式忽略 */ }
  location.hash = '#/login'
}
export const tokenPresent = () => !!getToken()
