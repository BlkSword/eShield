<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openModal } from '../stores/ui'
import type { ProtectionProject } from '../api/types'

const projects = ref<ProtectionProject[]>([])
onMounted(async () => { projects.value = await api.projects() })

const actionKind: Record<string, string> = { defend: 'tag-accent', pass: 'tag-ok', drop: 'tag-danger' }
async function save() {
  await api.saveProjects(projects.value)
  toast('防护项目已保存', `${projects.value.length} 个项目`, 'ok')
}
async function toggle(p: ProtectionProject, v: boolean) {
  p.enabled = v
  await save()
}
</script>

<template>
  <div class="page">
    <PanelCard title="防护项目" sub="按「目标地址 + 协议 + 端口」编排模块；PASS 低于黑名单、高于其他模块" flush>
      <template #actions>
        <TagPill :text="`${projects.length} 个项目`" kind="tag-accent" />
        <button class="btn btn-sm" @click="openModal('新增防护项目', 'project')">新增项目</button>
        <button class="btn btn-sm btn-primary" @click="save">保存</button>
      </template>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>项目</th><th>匹配条件</th><th>动作</th><th>启用模块</th><th>状态</th><th></th></tr></thead>
          <tbody>
            <tr v-for="p in projects" :key="p.name">
              <td><div class="cell-main">{{ p.name }}</div><div class="cell-sub">{{ p.description }}</div></td>
              <td><div class="mono">{{ p.protocol.toUpperCase() }} · {{ p.dport }}</div><div class="cell-sub mono">{{ (p.target_ips || []).join(', ') || '任意目标' }}</div></td>
              <td><TagPill :text="p.action.toUpperCase()" :kind="actionKind[p.action]" /></td>
              <td>
                <div class="row" style="flex-wrap: wrap; gap: 4px">
                  <TagPill v-for="m in p.enabled_modules" :key="m" :text="m" kind="tag-info" />
                  <span v-if="!p.enabled_modules.length" class="muted" style="font-size: 12px">按全局配置</span>
                </div>
              </td>
              <td><ToggleSwitch :model-value="p.enabled" @update:model-value="(v: boolean) => toggle(p, v)" /></td>
              <td class="col-actions">
                <button class="btn btn-sm btn-ghost" @click="openModal('编辑防护项目', 'project', p)">编辑</button>
                <button class="btn btn-sm btn-ghost" @click="projects = projects.filter((x) => x.name !== p.name); save()">删除</button>
              </td>
            </tr>
            <tr v-if="!projects.length"><td colspan="6" class="empty"><div class="title">暂无防护项目</div>未配置时所有流量走全局模块</td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>

    <div class="grid grid-3">
      <div class="kpi accent"><div class="k-label">DEFEND 项目</div><div class="k-value">{{ projects.filter((p) => p.action === 'defend').length }}</div><div class="k-foot"><span>按模块位图执行</span></div></div>
      <div class="kpi danger"><div class="k-label">DROP 项目</div><div class="k-value">{{ projects.filter((p) => p.action === 'drop').length }}</div><div class="k-foot"><span>命中即丢弃</span></div></div>
      <div class="kpi ok"><div class="k-label">PASS 项目</div><div class="k-value">{{ projects.filter((p) => p.action === 'pass').length }}</div><div class="k-foot"><span>跳过后续模块</span></div></div>
    </div>
  </div>
</template>
