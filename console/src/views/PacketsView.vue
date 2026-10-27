<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import { api } from '../api/client'
import { openDrawer } from '../stores/ui'
import type { PacketSample } from '../api/types'
import { fmtTime } from '../utils/format'

const rows = ref<PacketSample[]>([])
const q = ref('')
const action = ref('all')
const page = ref(1)
const pageSize = 25

const filtered = computed(() => {
  const n = q.value.trim().toLowerCase()
  return rows.value.filter((r) => {
    if (action.value !== 'all' && r.action !== action.value) return false
    if (n && !(r.src_ip + r.dst_ip + r.protocol + (r.payload_preview || '')).toLowerCase().includes(n)) return false
    return true
  })
})
const pages = computed(() => Math.max(1, Math.ceil(filtered.value.length / pageSize)))
const paged = computed(() => filtered.value.slice((page.value - 1) * pageSize, page.value * pageSize))

onMounted(async () => {
  rows.value = await api.packets()
})
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">包日志</div>
      <div class="page-meta">RingBuf 采样 <span class="mono">{{ rows.length }}</span> 条 · 采样率 1/16</div>
      <div class="page-actions"><span class="state"><span class="dot warn"></span>采样</span></div>
    </div>

    <PanelCard flush>
      <div class="toolbar">
        <div class="search-inline"><span>⌕</span><input v-model="q" placeholder="搜索源/目的 IP、协议或载荷" /></div>
        <select v-model="action" class="select" style="width: 118px">
          <option value="all">全部动作</option><option value="DROP">DROP</option><option value="PASS">PASS</option>
        </select>
        <div class="spacer"></div>
        <span class="muted">筛选后 {{ filtered.length }} 条</span>
      </div>
      <div class="table-wrap">
        <table class="dt">
          <thead>
            <tr><th>时间</th><th>源地址</th><th>目的地址</th><th>协议</th><th>TCP 标志</th><th>载荷预览</th><th>动作</th><th class="col-num">包长</th><th class="col-actions">操作</th></tr>
          </thead>
          <tbody>
            <tr v-for="r in paged" :key="r.id">
              <td class="mono muted">{{ fmtTime(r.timestamp_ns) }}</td>
              <td>
                <span class="mono cell-link" @click="openDrawer('IP 详情', 'ip', { ip: r.src_ip, count: 0 })">{{ r.src_ip }}</span>
              </td>
              <td class="mono">{{ r.dst_ip }}:{{ r.dst_port }}</td>
              <td class="muted">{{ r.protocol }}</td>
              <td class="mono muted">{{ r.tcp_flags || '—' }}</td>
              <td class="mono muted" style="max-width: 280px; overflow: hidden; text-overflow: ellipsis">{{ r.payload_preview || '—' }}</td>
              <td>
                <span class="state" :class="r.action === 'DROP' ? 'danger' : 'ok'">
                  <span class="dot" :class="r.action === 'DROP' ? 'danger' : 'ok'"></span>{{ r.action }}
                </span>
              </td>
              <td class="col-num mono">{{ r.length }}</td>
              <td class="col-actions">
                <div class="row-actions"><button class="btn btn-sm" @click="openDrawer('数据包详情', 'packet', r)">查看</button></div>
              </td>
            </tr>
            <tr v-if="!paged.length"><td colspan="9" class="empty"><div class="title">暂无采样包</div>开启包日志采样后，此处会显示 DROP 包的前 N 字节</td></tr>
          </tbody>
        </table>
      </div>
      <div class="tfoot">
        <span>第 {{ page }} / {{ pages }} 页 · 每页 {{ pageSize }} 条</span>
        <div class="pager">
          <button class="btn btn-sm" :disabled="page <= 1" @click="page--">上一页</button>
          <button class="btn btn-sm" :disabled="page >= pages" @click="page++">下一页</button>
        </div>
      </div>
    </PanelCard>
  </div>
</template>
