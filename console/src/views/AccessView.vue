<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openDrawer, openModal } from '../stores/ui'
import type { BlockEntry, PortAclEntry, WhitelistEntry } from '../api/types'
import { fmtDuration, fmtInt } from '../utils/format'

const tab = ref<'black' | 'white' | 'acl'>('black')
const blocks = ref<BlockEntry[]>([])
const whites = ref<WhitelistEntry[]>([])
const acls = ref<PortAclEntry[]>([])
const q = ref('')
const reason = ref('all')
const origin = ref('all')
const selected = ref<Set<string>>(new Set())
const busy = ref(false)

const shownBlocks = computed(() =>
  blocks.value.filter((b) => {
    if (reason.value !== 'all' && b.reason !== reason.value) return false
    if (origin.value !== 'all' && b.origin !== origin.value) return false
    const n = q.value.trim().toLowerCase()
    if (n && !(b.ip + b.reason + (b.last_reason || '') + b.origin).toLowerCase().includes(n)) return false
    return true
  }),
)
const reasons = computed(() => [...new Set(blocks.value.map((b) => b.reason).filter(Boolean))])
const origins = computed(() => [...new Set(blocks.value.map((b) => b.origin).filter(Boolean))])
const allChecked = computed(() => shownBlocks.value.length > 0 && shownBlocks.value.every((b) => selected.value.has(b.ip)))

async function load() {
  const [b, w, a] = await Promise.all([api.blacklist(), api.whitelist(), api.portAcl()])
  blocks.value = b
  whites.value = w
  acls.value = a
  const keep = new Set([...selected.value].filter((ip) => b.some((x) => x.ip === ip)))
  selected.value = keep
}
onMounted(load)
window.addEventListener('eshield:saved', () => load())

function toggle(ip: string) {
  const next = new Set(selected.value)
  next.has(ip) ? next.delete(ip) : next.add(ip)
  selected.value = next
}
function toggleAll() {
  const next = new Set(selected.value)
  if (allChecked.value) shownBlocks.value.forEach((b) => next.delete(b.ip))
  else shownBlocks.value.forEach((b) => next.add(b.ip))
  selected.value = next
}
async function unblock(ip: string) {
  await api.unblock(ip)
  toast('已解除封禁', ip, 'ok')
  load()
}
async function bulkUnblock() {
  busy.value = true
  const ips = [...selected.value]
  try {
    for (const ip of ips) await api.unblock(ip)
    toast(`已解除 ${ips.length} 条封禁`, '数据面立即生效', 'ok')
    selected.value = new Set()
    load()
  } finally {
    busy.value = false
  }
}
async function delWhite(cidr: string) {
  await api.delWhitelist(cidr)
  toast('已移除白名单', cidr, 'warn')
  load()
}
async function removeAcl(i: number) {
  acls.value.splice(i, 1)
  await api.savePortAcl(acls.value)
  toast('端口 ACL 已更新', '', 'ok')
}
async function saveAcl() {
  await api.savePortAcl(acls.value)
  toast('端口 ACL 已保存', `${acls.value.length} 条规则`, 'ok')
}
async function unblockAllExpired() {
  busy.value = true
  try {
    const expired = blocks.value.filter((b) => b.expires_ns && b.expires_ns <= Date.now() * 1e6)
    for (const b of expired) await api.unblock(b.ip)
    toast('已清理过期封禁', `${expired.length} 条`, 'ok')
    load()
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">访问控制</div>
      <div class="page-meta">
        黑名单 <span class="mono">{{ fmtInt(blocks.length) }}</span> · 白名单
        <span class="mono">{{ fmtInt(whites.length) }}</span> · ACL
        <span class="mono">{{ fmtInt(acls.length) }}</span>
      </div>
      <div class="page-actions">
        <button class="btn btn-sm" @click="load">刷新</button>
        <button v-if="tab === 'black'" class="btn btn-primary btn-sm" @click="openModal('封禁 IP', 'block-ip')">封禁 IP</button>
        <button v-if="tab === 'white'" class="btn btn-primary btn-sm" @click="openModal('添加白名单', 'whitelist')">添加白名单</button>
        <button v-if="tab === 'acl'" class="btn btn-primary btn-sm" @click="saveAcl">保存 ACL</button>
      </div>
    </div>

    <PanelCard flush>
      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'black' }" @click="tab = 'black'">
          黑名单 <span class="nav-badge">{{ blocks.length }}</span>
        </button>
        <button class="tab" :class="{ active: tab === 'white' }" @click="tab = 'white'">
          白名单 <span class="nav-badge">{{ whites.length }}</span>
        </button>
        <button class="tab" :class="{ active: tab === 'acl' }" @click="tab = 'acl'">
          端口 ACL <span class="nav-badge">{{ acls.length }}</span>
        </button>
      </div>

      <template v-if="tab === 'black'">
        <div class="toolbar">
          <div class="search-inline"><span>⌕</span><input v-model="q" placeholder="搜索 IP / 原因 / 来源" /></div>
          <select v-model="reason" class="select" style="width: 132px">
            <option value="all">全部原因</option>
            <option v-for="r in reasons" :key="r" :value="r">{{ r }}</option>
          </select>
          <select v-model="origin" class="select" style="width: 122px">
            <option value="all">全部来源</option>
            <option v-for="o in origins" :key="o" :value="o">{{ o }}</option>
          </select>
          <div class="spacer"></div>
          <span class="muted">筛选后 {{ fmtInt(shownBlocks.length) }} 条</span>
          <button class="btn btn-ghost btn-sm" :disabled="busy" @click="unblockAllExpired">清理已过期</button>
        </div>

        <div v-if="selected.size" class="bulkbar">
          <strong>已选 {{ selected.size }} 项</strong>
          <span class="muted">|</span>
          <button class="btn btn-sm btn-danger" :disabled="busy" @click="bulkUnblock()">解除封禁</button>
          <button class="btn btn-sm btn-ghost" @click="selected = new Set()">取消选择</button>
        </div>

        <div class="table-wrap">
          <table class="dt">
            <thead>
              <tr>
                <th class="col-check"><input type="checkbox" :checked="allChecked" @change="toggleAll" /></th>
                <th>IP 地址</th><th>封禁原因</th><th>来源</th><th class="col-num">命中次数</th>
                <th>到期时间</th><th class="col-actions">操作</th>
              </tr>
            </thead>
            <tbody>
              <tr v-for="b in shownBlocks" :key="b.ip" :class="{ selected: selected.has(b.ip) }">
                <td class="col-check"><input type="checkbox" :checked="selected.has(b.ip)" @change="toggle(b.ip)" /></td>
                <td>
                  <span class="mono cell-link" @click="openDrawer('IP 详情', 'ip', { ip: b.ip, count: b.hits })">{{ b.ip }}</span>
                </td>
                <td>
                  {{ b.reason }}
                  <span v-if="b.last_reason" class="muted">/ 叠加 {{ b.last_reason }}</span>
                </td>
                <td class="muted">{{ b.origin }}</td>
                <td class="col-num mono">{{ fmtInt(b.hits) }}</td>
                <td>
                  <span v-if="!b.expires_ns" class="state danger"><span class="dot danger"></span>永久</span>
                  <span v-else class="mono muted">{{ fmtDuration(b.expires_ns) }}</span>
                </td>
                <td class="col-actions">
                  <div class="row-actions">
                    <button class="btn btn-sm" @click="unblock(b.ip)">解除</button>
                    <button class="btn btn-sm" @click="openDrawer('IP 详情', 'ip', { ip: b.ip, count: b.hits })">详情</button>
                  </div>
                </td>
              </tr>
              <tr v-if="!shownBlocks.length"><td colspan="7" class="empty"><div class="title">黑名单为空</div>没有正在封禁的源地址</td></tr>
            </tbody>
          </table>
        </div>
        <div class="tfoot">
          <span>显示 {{ shownBlocks.length }} 条 · 白名单优先级最高，黑名单在防护项目之前生效</span>
        </div>
      </template>

      <template v-else-if="tab === 'white'">
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th>CIDR</th><th>备注</th><th class="col-actions">操作</th></tr></thead>
            <tbody>
              <tr v-for="w in whites" :key="w.cidr">
                <td class="mono cell-main">{{ w.cidr }}</td>
                <td class="muted">{{ w.note || '—' }}</td>
                <td class="col-actions">
                  <div class="row-actions"><button class="btn btn-sm" @click="delWhite(w.cidr)">移除</button></div>
                </td>
              </tr>
              <tr v-if="!whites.length"><td colspan="3" class="empty"><div class="title">暂无白名单</div>白名单命中的源地址跳过所有防护模块</td></tr>
            </tbody>
          </table>
        </div>
        <div class="panel-note">白名单来自配置文件与 API，优先级最高；修改后需同步到数据面。</div>
      </template>

      <template v-else>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th>协议</th><th>目的端口</th><th>动作</th><th class="col-actions">操作</th></tr></thead>
            <tbody>
              <tr v-for="(a, i) in acls" :key="i">
                <td class="muted">{{ a.protocol.toUpperCase() }}</td>
                <td class="mono cell-main">{{ a.dport }}</td>
                <td>
                  <span class="state" :class="a.action === 'accept' ? 'ok' : 'danger'">
                    <span class="dot" :class="a.action === 'accept' ? 'ok' : 'danger'"></span>
                    {{ a.action === 'accept' ? 'ACCEPT' : 'DENY' }}
                  </span>
                </td>
                <td class="col-actions">
                  <div class="row-actions"><button class="btn btn-sm" @click="removeAcl(i)">删除</button></div>
                </td>
              </tr>
              <tr v-if="!acls.length"><td colspan="4" class="empty"><div class="title">暂无端口 ACL</div>最多 32 条，空表时数据面跳过匹配</td></tr>
            </tbody>
          </table>
        </div>
        <div class="panel-note">端口 ACL 在白名单之后、其他防护模块之前匹配，最多 32 条；超出部分不会生效。</div>
      </template>
    </PanelCard>
  </div>
</template>
