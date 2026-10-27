<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import KpiCard from '../components/KpiCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openModal } from '../stores/ui'
import type { ProtectionProject } from '../api/types'

const projects = ref<ProtectionProject[]>([])
onMounted(async () => {
  projects.value = await api.projects()
})

const defendCount = computed(() => projects.value.filter((p) => p.action === 'defend').length)
const dropCount = computed(() => projects.value.filter((p) => p.action === 'drop').length)
const passCount = computed(() => projects.value.filter((p) => p.action === 'pass').length)

async function save() {
  await api.saveProjects(projects.value)
  toast('防护项目已保存', `${projects.value.length} 个项目`, 'ok')
}
async function toggle(p: ProtectionProject, v: boolean) {
  p.enabled = v
  await save()
}
async function remove(name: string) {
  projects.value = projects.value.filter((x) => x.name !== name)
  await save()
}
function tone(action: string) {
  return action === 'drop' ? 'danger' : action === 'pass' ? 'ok' : 'accent'
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">防护项目</div>
      <div class="page-meta">按「目标地址 + 协议 + 端口」编排模块；PASS 低于黑名单、高于其他模块</div>
      <div class="page-actions">
        <button class="btn btn-sm" @click="openModal('新增防护项目', 'project')">新增项目</button>
        <button class="btn btn-primary btn-sm" @click="save">保存</button>
      </div>
    </div>

    <div class="kpis">
      <KpiCard label="项目总数" :value="projects.length" format="int" :foot="`${projects.filter((p) => p.enabled).length} 个启用`" />
      <KpiCard label="DEFEND 项目" :value="defendCount" format="int" foot="按模块位图执行" />
      <KpiCard label="DROP 项目" :value="dropCount" format="int" foot="命中即丢弃" />
      <KpiCard label="PASS 项目" :value="passCount" format="int" foot="跳过后续模块" />
    </div>

    <PanelCard flush>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>项目</th><th>匹配条件</th><th>动作</th><th>启用模块</th><th>状态</th><th class="col-actions">操作</th></tr></thead>
          <tbody>
            <tr v-for="p in projects" :key="p.name">
              <td>
                <div class="cell-main">{{ p.name }}</div>
                <div class="cell-sub">{{ p.description }}</div>
              </td>
              <td>
                <div class="mono">{{ p.protocol.toUpperCase() }} · {{ p.dport }}</div>
                <div class="cell-sub mono">{{ (p.target_ips || []).join(', ') || '任意目标' }}</div>
              </td>
              <td>
                <span class="state" :class="tone(p.action)">
                  <span class="dot" :class="tone(p.action)"></span>{{ p.action.toUpperCase() }}
                </span>
              </td>
              <td class="muted">
                {{ p.enabled_modules.length ? p.enabled_modules.join(' · ') : '按全局配置' }}
              </td>
              <td><ToggleSwitch :model-value="p.enabled" @update:model-value="(v: boolean) => toggle(p, v)" /></td>
              <td class="col-actions">
                <div class="row-actions">
                  <button class="btn btn-sm" @click="openModal('编辑防护项目', 'project', p)">编辑</button>
                  <button class="btn btn-sm" @click="remove(p.name)">删除</button>
                </div>
              </td>
            </tr>
            <tr v-if="!projects.length"><td colspan="6" class="empty"><div class="title">暂无防护项目</div>未配置时所有流量走全局模块</td></tr>
          </tbody>
        </table>
      </div>
      <div class="panel-note">DEFEND 动作复用全局防御模块，并按 enabled_modules 位图过滤；未配置模块视为全开。</div>
    </PanelCard>
  </div>
</template>
