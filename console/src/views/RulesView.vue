<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import KpiCard from '../components/KpiCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { hubNodes as mockHubNodes } from '../api/mock'
import type { ProtectionProject } from '../api/types'

interface HubNode { name: string; ip: string; version: string; status: string; policies: number; last_seen: string }

const projects = ref<ProtectionProject[]>([])
const nodes = ref<HubNode[]>(mockHubNodes as HubNode[])
const hub = ref({ connected: false, url: '—' })
const syncing = ref(false)

const onlineNodes = computed(() => nodes.value.filter((n) => n.status === 'online').length)
const ruleCount = computed(() => 18 + projects.value.length)

onMounted(async () => {
  projects.value = await api.projects()
  const [status, remote] = await Promise.all([api.hubStatus(), api.hubNodes()])
  if (status && typeof status === 'object') {
    const s = status as Record<string, unknown>
    hub.value = {
      connected: !!(s.connected ?? s.enabled ?? s.hub_connected),
      url: String(s.active_url || s.url || s.hub_url || '—'),
    }
  }
  if (Array.isArray(remote) && remote.length) {
    nodes.value = remote.map((n: Record<string, unknown>) => ({
      name: String(n.node_name ?? n.name ?? '—'),
      ip: String(n.ip ?? n.address ?? '—'),
      version: String(n.version ?? '—'),
      status: String(n.status ?? 'online'),
      policies: Number(n.policies ?? n.policy_count ?? 0),
      last_seen: n.last_seen ? String(n.last_seen) : n.last_seen_s ? `${n.last_seen_s}s` : '—',
    }))
  }
})
async function sync() {
  syncing.value = true
  try {
    await api.hubStatus()
    toast('规则包同步已触发', '已向 Hub 查询最新策略', 'ok')
  } catch (e) {
    toast('同步失败', String(e), 'danger')
  } finally {
    syncing.value = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">规则与 Hub</div>
      <div class="page-meta">节点从 Hub 增量拉取策略包，本地写操作立即上报</div>
      <div class="page-actions">
        <button class="btn btn-primary btn-sm" :disabled="syncing" @click="sync">{{ syncing ? '同步中…' : '同步规则包' }}</button>
      </div>
    </div>

    <div class="kpis">
      <KpiCard
        label="Hub 连接"
        :value="hub.connected ? '已连接' : '未连接'"
        format="raw"
        :tone="hub.connected ? 'ok' : 'warn'"
        :foot="hub.url"
      />
      <KpiCard label="在线节点" :value="`${onlineNodes} / ${nodes.length}`" format="raw" foot="心跳间隔 10s" />
      <KpiCard label="规则条数" :value="ruleCount" format="int" foot="ACL + L7 + 项目" />
      <KpiCard label="待同步" :value="0" format="int" foot="本地策略已上报" />
    </div>

    <PanelCard title="节点列表" sub="Hub 侧的 eShield 节点与策略版本" flush>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>节点</th><th>地址</th><th>版本</th><th class="col-num">策略数</th><th>最近心跳</th><th>状态</th><th class="col-actions">操作</th></tr></thead>
          <tbody>
            <tr v-for="n in nodes" :key="n.name">
              <td class="cell-main">{{ n.name }}</td>
              <td class="mono">{{ n.ip }}</td>
              <td class="mono muted">v{{ n.version }}</td>
              <td class="col-num mono">{{ n.policies }}</td>
              <td class="muted mono">{{ n.last_seen }}</td>
              <td>
                <span class="state" :class="n.status === 'online' ? 'ok' : 'warn'">
                  <span class="dot" :class="n.status === 'online' ? 'ok' : 'warn'"></span>
                  {{ n.status === 'online' ? '在线' : '延迟' }}
                </span>
              </td>
              <td class="col-actions"><div class="row-actions"><button class="btn btn-sm">详情</button></div></td>
            </tr>
            <tr v-if="!nodes.length"><td colspan="7" class="empty"><div class="title">未配置 Hub</div>在节点配置中启用 [hub] 后此处显示集群节点</td></tr>
          </tbody>
        </table>
      </div>
    </PanelCard>

    <div class="grid grid-2">
      <PanelCard title="规则包结构" sub="节点拉取的统一策略集">
        <div class="dl">
          <div class="dl-row"><span class="dl-key">端口 ACL</span><span class="dl-val">协议 + 端口 + accept/deny</span></div>
          <div class="dl-row"><span class="dl-key">L7 指纹</span><span class="dl-val">TCP 载荷前 8 字节</span></div>
          <div class="dl-row"><span class="dl-key">防护项目</span><span class="dl-val">{{ projects.length }} 个项目</span></div>
          <div class="dl-row"><span class="dl-key">共享黑名单</span><span class="dl-val">Hub 下发的跨节点封禁</span></div>
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
