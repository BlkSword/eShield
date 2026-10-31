<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import KpiCard from '../components/KpiCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import type { AuditEntry } from '../api/types'
import { fmtDateTime, fmtInt } from '../utils/format'

const rows = ref<AuditEntry[]>([])
const q = ref('')
const actor = ref('all')
const verifying = ref(false)
onMounted(async () => {
  rows.value = await api.audit()
})

/** v0.5.0：校验审计哈希链，任何改写/删除/插入都会在断点处被发现。 */
async function verifyChain() {
  verifying.value = true
  try {
    const r = await api.auditVerify()
    if (r.enabled === false) {
      toast('文件审计未启用', r.message || '开启 [audit].enabled 后可用哈希链校验', 'warn')
    } else if (!r.ok) {
      toast('审计链校验失败', `首个断点序号 ${r.first_bad_seq ?? '—'}`, 'danger')
    } else {
      toast('审计链完整', `已校验 ${r.checked ?? 0} 条记录${r.path ? ' · ' + r.path : ''}`, 'ok')
    }
  } catch (e) {
    toast('校验失败', String(e), 'danger')
  } finally {
    verifying.value = false
  }
}

const filtered = computed(() => {
  const n = q.value.trim().toLowerCase()
  return rows.value.filter((r) => {
    if (actor.value !== 'all' && r.actor !== actor.value) return false
    if (n && !(r.action + r.target + r.detail + r.source_ip).toLowerCase().includes(n)) return false
    return true
  })
})
const actors = computed(() => [...new Set(rows.value.map((r) => r.actor).filter(Boolean))])
const apiCalls = computed(() => rows.value.filter((r) => r.actor === 'api').length)
const lastEntry = computed(() => rows.value[0])
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">审计日志</div>
      <div class="page-meta">控制面所有写操作均落盘，并支持 SSE 推送</div>
      <div class="page-actions">
        <span class="state"><span class="dot live"></span>SSE 推送</span>
        <button class="btn btn-sm" :disabled="verifying" @click="verifyChain">
          {{ verifying ? '校验中…' : '校验审计链' }}
        </button>
      </div>
    </div>

    <div class="kpis">
      <KpiCard label="审计记录" :value="rows.length" format="int" :foot="`筛选后 ${fmtInt(filtered.length)} 条`" />
      <KpiCard label="API 调用" :value="apiCalls" format="int" foot="来自受信管理网段" />
      <KpiCard label="操作者" :value="actors.length" format="int" :foot="actors.join(' / ') || '—'" />
      <KpiCard label="最近操作" :value="lastEntry ? fmtDateTime(lastEntry.timestamp_ns) : '—'" format="raw" :foot="lastEntry?.action || '—'" />
    </div>

    <PanelCard flush>
      <div class="toolbar">
        <div class="search-inline"><span>⌕</span><input v-model="q" placeholder="搜索动作 / 目标 / 来源" /></div>
        <select v-model="actor" class="select" style="width: 130px">
          <option value="all">全部来源</option>
          <option v-for="a in actors" :key="a" :value="a">{{ a }}</option>
        </select>
        <div class="spacer"></div>
        <span class="muted">{{ fmtInt(filtered.length) }} 条</span>
      </div>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>目标</th><th>来源 IP</th><th>详情</th></tr></thead>
          <tbody>
            <tr v-for="r in filtered" :key="r.id">
              <td class="mono muted">{{ fmtDateTime(r.timestamp_ns) }}</td>
              <td class="muted">{{ r.actor }}</td>
              <td class="cell-main">{{ r.action }}</td>
              <td class="mono">{{ r.target }}</td>
              <td class="mono muted">{{ r.source_ip }}</td>
              <td class="muted" style="max-width: 380px; overflow: hidden; text-overflow: ellipsis">{{ r.detail }}</td>
            </tr>
            <tr v-if="!filtered.length"><td colspan="6" class="empty"><div class="title">暂无审计记录</div>控制面写操作会自动记录</td></tr>
          </tbody>
        </table>
      </div>
      <div class="tfoot"><span>审计记录可在服务端配置为 JSON Lines 文件持久化</span></div>
    </PanelCard>
  </div>
</template>
