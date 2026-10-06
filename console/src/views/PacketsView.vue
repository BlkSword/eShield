<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import { api } from '../api/client'
import { openDrawer } from '../stores/ui'
import type { PacketSample } from '../api/types'
import { fmtTime } from '../utils/format'

const rows = ref<PacketSample[]>([])
const q = ref('')
onMounted(async () => { rows.value = await api.packets() })
function filtered() {
  const n = q.value.trim().toLowerCase()
  return n ? rows.value.filter((r) => (r.src_ip + r.dst_ip + r.protocol).toLowerCase().includes(n)) : rows.value
}
</script>
<template>
  <div class="page">
    <PanelCard title="包日志" :sub="`RingBuf 采样 ${rows.length} 条，采样率 1/16`" flush>
      <template #actions><TagPill text="采样" kind="tag-violet" /></template>
      <div class="table-toolbar">
        <div class="search-inline"><span class="muted">⌕</span><input v-model="q" placeholder="搜索源/目的 IP 或协议" /></div>
        <div style="flex: 1"></div>
      </div>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>时间</th><th>源地址</th><th>目的地址</th><th>协议</th><th>TCP 标志</th><th>载荷预览</th><th>动作</th><th class="col-num">包长</th><th></th></tr></thead>
          <tbody>
            <tr v-for="r in filtered()" :key="r.id">
              <td class="mono muted nowrap">{{ fmtTime(r.timestamp_ns) }}</td>
              <td><span class="mono cell-main" style="cursor: pointer" @click="openDrawer('IP 详情', 'ip', { ip: r.src_ip, count: 0 })">{{ r.src_ip }}</span></td>
              <td class="mono">{{ r.dst_ip }}:{{ r.dst_port }}</td>
              <td><TagPill :text="r.protocol" :kind="r.protocol === 'TCP' ? 'tag-info' : 'tag-violet'" /></td>
              <td class="mono muted">{{ r.tcp_flags || '—' }}</td>
              <td class="mono muted" style="max-width: 260px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ r.payload_preview || '—' }}</td>
              <td><TagPill :text="r.action" :kind="r.action === 'DROP' ? 'tag-danger' : 'tag-ok'" /></td>
              <td class="col-num mono">{{ r.length }}</td>
              <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="openDrawer('数据包详情', 'packet', r)">查看</button></td>
            </tr>
            <tr v-if="!filtered().length"><td colspan="9" class="empty"><div class="title">暂无采样包</div>开启包日志采样后此处会显示 DROP 包</td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>
  </div>
</template>
