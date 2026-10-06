<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import { navGroups } from '../router'
import { store } from '../stores/app'

const props = defineProps<{ open: boolean }>()
const emit = defineEmits<{ (e: 'navigate'): void }>()
const route = useRoute()
const active = computed(() => route.path)
const modeText = computed(() => (store.stats ? 'XDP native' : '连接中'))
</script>

<template>
  <aside class="sidebar" :class="{ open: props.open }">
    <div class="brand">
      <div class="brand-mark"></div>
      <div>
        <div class="brand-name">eShield</div>
        <div class="brand-sub">主机防护控制台</div>
      </div>
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
          <span v-if="item.path === '/attacks' && store.stats" class="nav-badge">
            {{ Math.round((store.stats.current_dps || 0) / 1000) }}k
          </span>
        </router-link>
      </div>
    </div>
    <div class="side-foot">
      <div class="node-card">
        <div class="title">
          <span class="dot pulse" :style="{ color: store.stats ? 'var(--ok)' : 'var(--warn)' }"></span>
          {{ modeText }}
        </div>
        <div class="meta">
          <div class="spread"><span>接口</span><b>{{ (store.stats && 'eth0') || '—' }}</b></div>
          <div class="spread"><span>版本</span><b>v0.4.6</b></div>
        </div>
      </div>
    </div>
  </aside>
</template>
