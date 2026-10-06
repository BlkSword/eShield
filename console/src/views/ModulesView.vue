<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api } from '../api/client'
import { store, toast } from '../stores/app'
import type { ModuleState } from '../api/types'
import { fmtCompact } from '../utils/format'

const modules = ref<ModuleState[]>([])
const loading = ref(true)
const activeGroup = ref('全部')
const groups = computed(() => ['全部', ...new Set(modules.value.map((m) => m.group))])
const shown = computed(() => (activeGroup.value === '全部' ? modules.value : modules.value.filter((m) => m.group === activeGroup.value)))
const enabledCount = computed(() => modules.value.filter((m) => m.enabled).length)

const s = computed(() => store.stats)
onMounted(async () => {
  modules.value = await api.modules(s.value as any)
  loading.value = false
})

async function toggle(m: ModuleState, v: boolean) {
  m.enabled = v
  try {
    await api.patchModule(m.id, v)
    toast(`${m.name} 已${v ? '启用' : '停用'}`, '运行时生效，无需重启', v ? 'ok' : 'warn')
  } catch (e) {
    m.enabled = !v
    toast('切换失败', String(e), 'danger')
  }
}
function statOf(m: ModuleState) {
  if (!m.statsKey || !s.value) return null
  return s.value[m.statsKey] as number
}
</script>

<template>
  <div class="page">
    <div class="grid grid-4">
      <div class="kpi accent"><div class="k-label">已启用模块</div><div class="k-value">{{ enabledCount }}<small>/ {{ modules.length }}</small></div><div class="k-foot"><span>运行时热生效</span></div></div>
      <div class="kpi danger"><div class="k-label">速率限制拦截</div><div class="k-value">{{ fmtCompact(s?.rate_limited || 0).value }}{{ fmtCompact(s?.rate_limited || 0).unit }}</div><div class="k-foot"><span>累计</span></div></div>
      <div class="kpi warn"><div class="k-label">SYN Flood 拦截</div><div class="k-value">{{ fmtCompact(s?.syn_flood_blocked || 0).value }}{{ fmtCompact(s?.syn_flood_blocked || 0).unit }}</div><div class="k-foot"><span>累计</span></div></div>
      <div class="kpi violet"><div class="k-label">L7 拦截</div><div class="k-value">{{ fmtCompact(s?.l7_blocked || 0).value }}{{ fmtCompact(s?.l7_blocked || 0).unit }}</div><div class="k-foot"><span>累计</span></div></div>
    </div>

    <div class="segmented" style="align-self: flex-start">
      <button v-for="g in groups" :key="g" :class="{ active: activeGroup === g }" @click="activeGroup = g">{{ g }}</button>
    </div>

    <div class="module-grid">
      <div v-for="m in shown" :key="m.id" class="module-card" :class="{ enabled: m.enabled }">
        <div class="mc-head">
          <div class="col" style="gap: 2px; min-width: 0">
            <div class="mc-name">{{ m.name }}</div>
            <TagPill :text="m.group" kind="tag-accent" />
          </div>
          <div style="flex: 1"></div>
          <ToggleSwitch :model-value="m.enabled" @update:model-value="(v: boolean) => toggle(m, v)" />
        </div>
        <div class="mc-desc">{{ m.description }}</div>
        <div v-if="m.fields.length" class="module-fields">
          <div v-for="f in m.fields" :key="f.key" class="field">
            <label class="field-label">{{ f.label }}</label>
            <input v-if="f.type === 'number'" class="input" :value="f.value as number" />
            <ToggleSwitch v-else :model-value="f.value as boolean" @update:model-value="(v: boolean) => (f.value = v)" />
          </div>
        </div>
        <div class="mc-foot">
          <div v-if="statOf(m) !== null" class="mc-stats">
            <b>{{ fmtCompact(statOf(m)).value }}{{ fmtCompact(statOf(m)).unit }}</b>
            <span class="muted">累计拦截</span>
          </div>
          <div v-else class="muted" style="font-size: 12px">无独立计数器</div>
          <TagPill :text="m.enabled ? '运行中' : '已停用'" :kind="m.enabled ? 'tag-ok' : ''" dot />
        </div>
      </div>
    </div>
  </div>
</template>
