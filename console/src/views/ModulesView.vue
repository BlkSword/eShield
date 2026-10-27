<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import KpiCard from '../components/KpiCard.vue'
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
  modules.value = await api.modules(s.value as never)
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
function compact(n: number | null) {
  if (n === null) return '—'
  const c = fmtCompact(n)
  return c.value + c.unit
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">防护模块</div>
      <div class="page-meta">运行时热生效，无需重启；开关会直接写入数据面运行时配置</div>
      <div class="page-actions">
        <span class="state" :class="loading ? 'warn' : 'ok'"><span class="dot" :class="loading ? 'warn' : 'ok'"></span>{{ loading ? '加载中' : `${enabledCount} / ${modules.length} 启用` }}</span>
      </div>
    </div>

    <div class="kpis">
      <KpiCard label="已启用模块" :value="enabledCount" format="int" :foot="`共 ${modules.length} 个模块`" />
      <KpiCard label="速率限制拦截" :value="s?.rate_limited || 0" :foot="'累计'" />
      <KpiCard label="SYN Flood 拦截" :value="s?.syn_flood_blocked || 0" :foot="'累计（实验特性）'" />
      <KpiCard label="L7 拦截" :value="s?.l7_blocked || 0" :foot="'累计'" />
    </div>

    <div class="segmented" style="align-self: flex-start">
      <button v-for="g in groups" :key="g" :class="{ active: activeGroup === g }" @click="activeGroup = g">{{ g }}</button>
    </div>

    <div class="module-grid">
      <div v-for="m in shown" :key="m.id" class="module-card">
        <div class="mc-head">
          <div class="col" style="gap: 1px; min-width: 0">
            <div class="mc-name">{{ m.name }}</div>
            <div class="muted" style="font-size: 11px">{{ m.group }}</div>
          </div>
          <div class="spacer"></div>
          <span class="state" :class="m.enabled ? 'ok' : ''">
            <span class="dot" :class="m.enabled ? 'ok' : ''"></span>{{ m.enabled ? '运行中' : '已停用' }}
          </span>
          <ToggleSwitch :model-value="m.enabled" @update:model-value="(v: boolean) => toggle(m, v)" />
        </div>
        <div class="mc-desc">{{ m.description }}</div>
        <div v-if="m.fields && m.fields.length" class="module-fields">
          <div v-for="f in m.fields" :key="f.key" class="field">
            <label class="field-label">{{ f.label }}</label>
            <input v-if="f.type === 'number'" class="input mono" :value="f.value as number" />
            <ToggleSwitch v-else :model-value="f.value as boolean" @update:model-value="(v: boolean) => (f.value = v)" />
          </div>
        </div>
        <div class="mc-foot">
          <div v-if="statOf(m) !== null" class="mc-stats">
            <b>{{ compact(statOf(m)) }}</b><span class="muted">累计拦截</span>
          </div>
          <div v-else class="muted" style="font-size: 11.5px">无独立计数器</div>
          <span class="muted mono" style="font-size: 10.5px">{{ m.id }}</span>
        </div>
      </div>
    </div>
  </div>
</template>
