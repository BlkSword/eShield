<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, ref } from 'vue'
import SideNav from './components/SideNav.vue'
import TopBar from './components/TopBar.vue'
import SlideDrawer from './components/SlideDrawer.vue'
import ModalDialog from './components/ModalDialog.vue'
import CommandPalette from './components/CommandPalette.vue'
import ToastHost from './components/ToastHost.vue'
import { commandOpen, initTheme, refresh, store } from './stores/app'
import { useRoute, useRouter } from 'vue-router'

const sidebarOpen = ref(false)
const ready = ref(!location.protocol.startsWith('http'))
const router = useRouter()
const route = useRoute()
const isLogin = computed(() => route.path === '/login')
let timer: number | undefined
let es: EventSource | undefined

function onKey(e: KeyboardEvent) {
  const target = e.target as HTMLElement
  const typing = target && (target.tagName === 'INPUT' || target.tagName === 'TEXTAREA' || target.isContentEditable)
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault()
    commandOpen.value = true
  } else if (e.key === 'Escape') {
    commandOpen.value = false
  } else if (!typing && e.key === '/') {
    e.preventDefault()
    commandOpen.value = true
  } else if (!typing && e.key.toLowerCase() === 'r' && !e.ctrlKey && !e.metaKey) {
    refresh(true)
  }
}

async function bootstrapAuth() {
  if (!location.protocol.startsWith('http')) { ready.value = true; return }
  try {
    const res = await fetch('/api/auth/check', { credentials: 'same-origin' })
    const hash = location.hash || '#/'
    if (res.ok) {
      if (hash === '#/' || hash.startsWith('#/login')) router.replace('/overview')
    } else if (!hash.startsWith('#/login')) {
      router.replace('/login')
    }
  } catch { /* static preview / demo mode */ }
  ready.value = true
  refresh()
}

onMounted(() => {
  initTheme()
  bootstrapAuth()
  timer = window.setInterval(() => refresh(), 3000)
  window.addEventListener('keydown', onKey)
  window.addEventListener('eshield:saved', () => refresh(true))
  // Live audit stream is only useful when the console is served by eShield.
  if (location.protocol.startsWith('http')) {
    try {
      es = new EventSource('/api/audit/stream')
      es.onerror = () => { es?.close(); es = undefined }
    } catch { /* demo mode */ }
  }
})
onBeforeUnmount(() => {
  if (timer) clearInterval(timer)
  es?.close()
  window.removeEventListener('keydown', onKey)
})
</script>

<template>
  <div v-if="!ready" class="login-page">
    <div class="muted">正在验证访问令牌…</div>
  </div>
  <router-view v-else-if="isLogin" />
  <div v-else class="app-shell">
    <SideNav :open="sidebarOpen" @navigate="sidebarOpen = false" />
    <div class="main">
      <TopBar @toggle-sidebar="sidebarOpen = !sidebarOpen" />
      <main class="content">
        <router-view v-slot="{ Component }">
          <transition name="fade" mode="out-in">
            <component :is="Component" />
          </transition>
        </router-view>
      </main>
    </div>
  </div>
  <SlideDrawer />
  <ModalDialog />
  <CommandPalette />
  <ToastHost />
</template>

<style>
.fade-enter-active, .fade-leave-active { transition: opacity 0.12s ease; }
.fade-enter-from, .fade-leave-to { opacity: 0; }
</style>
