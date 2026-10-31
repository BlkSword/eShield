<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openDrawer } from '../stores/ui'
import type { AttackEvent } from '../api/types'
import { fmtInt, fmtTime, reasonLabel } from '../utils/format'

const rows = ref<AttackEvent[]>([])
const total = ref(0)
const loading = ref(true)
const q = ref('')
const proto = ref('all')
const action = ref('all')
const selected = ref<Set<string>>(new Set())
const page = ref(1)
const pageSize = 20

const filtered = computed(() =>
  rows.value.filter((r) => {
    if (proto.value !== 'all' && r.protocol.toLowerCase() !== proto.value) return false
    if (action.value !== 'all' && r.action !== action.value) return false
    const needle = q.value.trim().toLowerCase()
    if (needle && !(r.src_ip + r.dst_ip + r.rule + r.reason).toLowerCase().includes(needle)) return false
    return true
  }),
)
const pages = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize)))
const paged = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))
const allChecked = computed(() => paged.value.length > 0 && paged.value.every((r) => selected.value.has(r.id)))

async function load() {
  loading.value = true
  rows.value = await api.attackEvents()
  total.value = rows.value.length
  page.value = 1
  loading.value = false
}
onMounted(load)

function toggle(id: string) {
  const next = new Set(selected.value)
  next.has(id) ? next.delete(id) : next.add(id)
  selected.value = next
}
function toggleAll() {
  const next = new Set(selected.value)
  if (allChecked.value) paged.value.forEach((r) => next.delete(r.id))
  else paged.value.forEach((r) => next.add(r.id))
  selected.value = next
}
async function bulkBlock() {
  const ips = [...new Set(rows.value.filter((r) => selected.value.has(r.id)).map((r) => r.src_ip))]
  for (const ip of ips) await api.block(ip, 3600)
  toast(`已封禁 ${ips.length} 个源地址`, '有效期 1 小时', 'ok')
  selected.value = new Set()
  load()
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">攻击事件</div>
      <div class="page-meta">共 <span class="mono">{{ fmtInt(total) }}</span> 条采样记录 · 筛选后 {{ fmtInt(filtered.length) }} 条</div>
      <div class="page-actions">
        <span class="state"><span class="dot live"></span>实时同步</span>
        <button class="btn btn-sm" @click="load">刷新</button>
      </div>
    </div>

    <PanelCard flush>
      <div class="toolbar">
        <div class="search-inline"><span>⌕</span><input v-model="q" placeholder="搜索 IP / 规则 / 原因" /></div>
        <select v-model="proto" class="select" style="width: 118px">
          <option value="all">全部协议</option><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option>
        </select>
        <select v-model="action" class="select" style="width: 118px">
          <option value="all">全部动作</option><option value="DROP">DROP</option><option value="PASS">PASS</option>
        </select>
        <div class="spacer"></div>
        <span class="muted">第 {{ page }} / {{ pages }} 页</span>
      </div>

      <div v-if="selected.size" class="bulkbar">
        <strong>已选 {{ selected.size }} 条</strong>
        <span class="muted">|</span>
        <button class="btn btn-sm btn-danger" @click="bulkBlock()">批量封禁源 IP</button>
        <button class="btn btn-sm btn-ghost" @click="selected = new Set()">取消选择</button>
      </div>

      <div class="table-wrap">
        <table class="dt">
          <thead>
            <tr>
              <th class="col-check"><input type="checkbox" :checked="allChecked" @change="toggleAll" /></th>
              <th>时间</th><th>源地址</th><th>目的地址</th><th>协议</th><th>规则</th><th>动作</th>
              <th class="col-num">包长</th><th class="col-actions">操作</th>
            </tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id" :class="{ selected: selected.has(r.id) }">
              <td class="col-check"><input type="checkbox" :checked="selected.has(r.id)" @change="toggle(r.id)" /></td>
              <td class="mono muted">{{ fmtTime(r.timestamp_ns) }}</td>
              <td>
                <span class="mono cell-link" @click="openDrawer('IP 详情', 'ip', { ip: r.src_ip, count: 0 })">{{ r.src_ip }}</span>
              </td>
              <td class="mono">{{ r.dst_ip }}:{{ r.dst_port }}</td>
              <td class="muted">{{ r.protocol }}</td>
              <td>{{ reasonLabel(r.reason) }}</td>
              <td>
                <span class="state" :class="r.action === 'DROP' ? 'danger' : 'ok'">
                  <span class="dot" :class="r.action === 'DROP' ? 'danger' : 'ok'"></span>{{ r.action }}
                </span>
              </td>
              <td class="col-num mono">{{ r.length }}</td>
              <td class="col-actions">
                <div class="row-actions"><button class="btn btn-sm" @click="openDrawer('事件详情', 'event', r)">详情</button></div>
              </td>
            </tr>
            <tr v-if="!paged.length"><td colspan="9" class="empty"><div class="title">没有匹配的事件</div>调整筛选条件或稍后刷新</td></tr>
          </tbody>
        </table>
      </div>

      <div class="tfoot">
        <span>每页 {{ pageSize }} 条</span>
        <div class="pager">
          <button class="btn btn-sm" :disabled="page <= 1" @click="page--">上一页</button>
          <button class="btn btn-sm" :disabled="page >= pages" @click="page++">下一页</button>
        </div>
      </div>
    </PanelCard>
  </div>
</template>
