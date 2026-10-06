<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openDrawer, openModal } from '../stores/ui'
import type { BlockEntry, PortAclEntry, WhitelistEntry } from '../api/types'
import { fmtDuration, fmtInt, fmtDateTime } from '../utils/format'

const tab = ref<'black' | 'white' | 'acl'>('black')
const blocks = ref<BlockEntry[]>([])
const whites = ref<WhitelistEntry[]>([])
const acls = ref<PortAclEntry[]>([])
const q = ref('')

const shownBlocks = computed(() => blocks.value.filter((b) => !q.value || (b.ip + b.reason + b.origin).includes(q.value)))

async function load() {
  const [b, w, a] = await Promise.all([api.blacklist(), api.whitelist(), api.portAcl()])
  blocks.value = b; whites.value = w; acls.value = a
}
onMounted(load)
window.addEventListener('eshield:saved', () => load())

async function unblock(ip: string) {
  await api.unblock(ip)
  toast('已解除封禁', ip, 'ok')
  load()
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
</script>

<template>
  <div class="page">
    <PanelCard title="访问控制" sub="白名单优先级最高；黑名单在防护项目之前生效" flush>
      <template #actions>
        <button v-if="tab === 'black'" class="btn btn-sm btn-danger" @click="openModal('封禁 IP', 'block-ip')">封禁 IP</button>
        <button v-if="tab === 'white'" class="btn btn-sm btn-primary" @click="openModal('添加白名单', 'whitelist')">添加白名单</button>
        <button v-if="tab === 'acl'" class="btn btn-sm btn-primary" @click="saveAcl">保存 ACL</button>
      </template>
      <div class="tabs">
        <button class="tab" :class="{ active: tab === 'black' }" @click="tab = 'black'">黑名单 <span class="nav-badge">{{ blocks.length }}</span></button>
        <button class="tab" :class="{ active: tab === 'white' }" @click="tab = 'white'">白名单 <span class="nav-badge">{{ whites.length }}</span></button>
        <button class="tab" :class="{ active: tab === 'acl' }" @click="tab = 'acl'">端口 ACL <span class="nav-badge">{{ acls.length }}</span></button>
      </div>

      <div v-if="tab === 'black'">
        <div class="table-toolbar"><div class="search-inline"><span class="muted">⌕</span><input v-model="q" placeholder="搜索 IP / 原因 / 来源" /></div></div>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th>IP 地址</th><th>封禁原因</th><th>来源</th><th>命中次数</th><th>到期时间</th><th></th></tr></thead>
            <tbody>
              <tr v-for="b in shownBlocks" :key="b.ip">
                <td><span class="mono cell-main" style="cursor: pointer" @click="openDrawer('IP 详情', 'ip', { ip: b.ip, count: b.hits })">{{ b.ip }}</span></td>
                <td>{{ b.reason }}</td>
                <td><TagPill :text="b.origin" :kind="b.origin === 'api' ? 'tag-info' : b.origin === 'adaptive' ? 'tag-violet' : 'tag-warn'" /></td>
                <td class="mono">{{ fmtInt(b.hits) }}</td>
                <td><span v-if="!b.expires_ns" class="tag tag-danger">永久</span><span v-else class="muted mono">{{ fmtDuration(b.expires_ns) }}</span></td>
                <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="unblock(b.ip)">解除</button></td>
              </tr>
              <tr v-if="!shownBlocks.length"><td colspan="6" class="empty"><div class="title">黑名单为空</div>没有正在封禁的源地址</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div v-else-if="tab === 'white'">
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th>CIDR</th><th>备注</th><th>创建时间</th><th></th></tr></thead>
            <tbody>
              <tr v-for="w in whites" :key="w.cidr">
                <td class="mono cell-main">{{ w.cidr }}</td>
                <td>{{ w.note }}</td>
                <td class="muted mono">{{ fmtDateTime(Date.now() * 1e6) }}</td>
                <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="delWhite(w.cidr)">移除</button></td>
              </tr>
              <tr v-if="!whites.length"><td colspan="4" class="empty">暂无白名单</td></tr>
            </tbody>
          </table>
        </div>
      </div>

      <div v-else>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th>协议</th><th>目的端口</th><th>动作</th><th></th></tr></thead>
            <tbody>
              <tr v-for="(a, i) in acls" :key="i">
                <td><TagPill :text="a.protocol.toUpperCase()" kind="tag-info" /></td>
                <td class="mono cell-main">{{ a.dport }}</td>
                <td><TagPill :text="a.action === 'accept' ? 'ACCEPT' : 'DENY'" :kind="a.action === 'accept' ? 'tag-ok' : 'tag-danger'" /></td>
                <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="removeAcl(i)">删除</button></td>
              </tr>
              <tr v-if="!acls.length"><td colspan="4" class="empty">暂无端口 ACL</td></tr>
            </tbody>
          </table>
        </div>
        <div class="panel-body muted" style="font-size: 12px">端口 ACL 在数据面最先匹配（白名单之后），最多 32 条；超出部分不会生效。</div>
      </div>
    </PanelCard>
  </div>
</template>
