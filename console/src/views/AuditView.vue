<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import { api } from '../api/client'
import type { AuditEntry } from '../api/types'
import { fmtDateTime } from '../utils/format'

const rows = ref<AuditEntry[]>([])
const q = ref('')
const actor = ref('all')
onMounted(async () => { rows.value = await api.audit() })
function filtered() {
  const n = q.value.trim().toLowerCase()
  return rows.value.filter((r) => {
    if (actor.value !== 'all' && r.actor !== actor.value) return false
    if (n && !(r.action + r.target + r.detail + r.source_ip).toLowerCase().includes(n)) return false
    return true
  })
}
</script>
<template>
  <div class="page">
    <div class="grid grid-3">
      <div class="kpi ok"><div class="k-label">今日操作</div><div class="k-value">{{ rows.length }}</div><div class="k-foot"><span>覆盖封禁、配置、情报同步</span></div></div>
      <div class="kpi accent"><div class="k-label">API 调用</div><div class="k-value">{{ rows.filter((r) => r.actor === 'api').length }}</div><div class="k-foot"><span>来自受信管理网段</span></div></div>
      <div class="kpi violet"><div class="k-label">最近一次登录</div><div class="k-value" style="font-size: 17px">{{ fmtDateTime(rows[0]?.timestamp_ns || Date.now() * 1e6) }}</div><div class="k-foot"><span>admin · 172.23.83.41</span></div></div>
    </div>
    <PanelCard title="审计日志" sub="控制面所有写操作均落盘并支持推送" flush>
      <template #actions><TagPill text="SSE 推送" kind="tag-ok" dot /></template>
      <div class="table-toolbar">
        <div class="search-inline"><span class="muted">⌕</span><input v-model="q" placeholder="搜索动作 / 目标 / 来源" /></div>
        <select v-model="actor" class="select" style="width: 130px"><option value="all">全部来源</option><option value="admin">admin</option><option value="api">api</option><option value="system">system</option></select>
      </div>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>目标</th><th>来源 IP</th><th>详情</th></tr></thead>
          <tbody>
            <tr v-for="r in filtered()" :key="r.id">
              <td class="mono muted nowrap">{{ fmtDateTime(r.timestamp_ns) }}</td>
              <td><TagPill :text="r.actor" :kind="r.actor === 'api' ? 'tag-info' : r.actor === 'system' ? 'tag-violet' : ''" /></td>
              <td class="cell-main">{{ r.action }}</td>
              <td class="mono">{{ r.target }}</td>
              <td class="mono muted">{{ r.source_ip }}</td>
              <td class="mono muted" style="max-width: 320px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ r.detail }}</td>
            </tr>
            <tr v-if="!filtered().length"><td colspan="6" class="empty"><div class="title">暂无审计记录</div></td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>
  </div>
</template>
