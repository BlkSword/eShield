<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { hubNodes } from '../api/mock'
import type { ProtectionProject } from '../api/types'

const projects = ref<ProtectionProject[]>([])
const syncing = ref(false)
onMounted(async () => { projects.value = await api.projects() })
function sync() {
  syncing.value = true
  toast('规则包同步已触发', '向 Hub 拉取增量策略', 'info')
  setTimeout(() => (syncing.value = false), 1200)
}
</script>

<template>
  <div class="page">
    <div class="grid grid-4">
      <div class="kpi ok"><div class="k-label">Hub 连接</div><div class="k-value" style="font-size: 17px">已连接</div><div class="k-foot"><span>wss://hub.eshield.local:9930</span></div></div>
      <div class="kpi accent"><div class="k-label">在线节点</div><div class="k-value">{{ hubNodes.filter((n) => n.status === 'online').length }}<small>/ {{ hubNodes.length }}</small></div><div class="k-foot"><span>心跳间隔 10s</span></div></div>
      <div class="kpi violet"><div class="k-label">规则条数</div><div class="k-value">{{ 18 + projects.length }}</div><div class="k-foot"><span>ACL + L7 + 项目</span></div></div>
      <div class="kpi warn"><div class="k-label">待同步</div><div class="k-value">0</div><div class="k-foot"><span>本地策略已上报</span></div></div>
    </div>

    <PanelCard title="节点列表" sub="Hub 侧的 eShield 节点与策略版本" flush>
      <template #actions>
        <button class="btn btn-sm" :disabled="syncing" @click="sync">同步规则包</button>
      </template>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>节点</th><th>地址</th><th>版本</th><th class="col-num">策略数</th><th>最近心跳</th><th>状态</th><th></th></tr></thead>
          <tbody>
            <tr v-for="n in hubNodes" :key="n.name">
              <td class="cell-main">{{ n.name }}</td>
              <td class="mono">{{ n.ip }}</td>
              <td><TagPill :text="'v' + n.version" :kind="n.version === '0.4.6' ? 'tag-ok' : 'tag-warn'" /></td>
              <td class="col-num mono">{{ n.policies }}</td>
              <td class="muted mono">{{ n.last_seen }}</td>
              <td><TagPill :text="n.status === 'online' ? '在线' : '延迟'" :kind="n.status === 'online' ? 'tag-ok' : 'tag-warn'" dot /></td>
              <td class="col-actions"><button class="btn btn-sm btn-ghost">详情</button></td>
            </tr>
          </tbody>
        </table>
      </div>
    </PanelCard>

    <div class="grid grid-2">
      <PanelCard title="规则包结构" sub="节点拉取的统一策略集">
        <div class="col" style="gap: 0">
          <div class="setting-row"><div class="sr-main"><div class="sr-title">端口 ACL</div><div class="sr-desc">协议 + 端口 + accept/deny</div></div><TagPill text="4 条" kind="tag-info" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">L7 指纹</div><div class="sr-desc">TCP 载荷前 8 字节</div></div><TagPill text="4 条" kind="tag-info" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">防护项目</div><div class="sr-desc">目标 + 端口 + 模块位图</div></div><TagPill :text="`${projects.length} 个`" kind="tag-info" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">共享黑名单</div><div class="sr-desc">Hub 下发的跨节点封禁</div></div><TagPill text="12 条" kind="tag-info" /></div>
        </div>
      </PanelCard>
      <PanelCard title="同步策略" sub="冲突处理与回滚">
        <dl class="kv">
          <dt>拉取模式</dt><dd>增量 since + tombstone</dd>
          <dt>冲突策略</dt><dd>节点本地优先，Hub 标记冲突</dd>
          <dt>上报周期</dt><dd>30s 或写操作立即触发</dd>
          <dt>失败重试</dt><dd>指数退避，最大 5 分钟</dd>
          <dt>规则回滚</dt><dd>保留最近 5 个版本</dd>
        </dl>
      </PanelCard>
    </div>
  </div>
</template>
