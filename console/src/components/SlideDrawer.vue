<script setup lang="ts">
import { computed, ref } from 'vue'
import { closeDrawer, drawer } from '../stores/ui'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { fmtAgo, fmtDateTime, fmtInt } from '../utils/format'
import { makeAttackEvents } from '../api/mock'
import TagPill from './TagPill.vue'

const busy = ref(false)
const kind = computed(() => drawer.kind)
const p = computed(() => drawer.payload || {})

const recent = computed(() => {
  if (kind.value !== 'ip') return []
  return makeAttackEvents(400).filter((e) => e.src_ip === p.value.ip).slice(0, 8)
})
const trust = computed(() => {
  const hits = p.value.count || p.value.hits || 0
  if (hits > 1_000_000) return { label: '恶意', kind: 'tag-danger' }
  if (hits > 100_000) return { label: '可疑', kind: 'tag-warn' }
  if (hits > 0) return { label: '中性', kind: 'tag-info' }
  return { label: '未知', kind: '' }
})

async function block() {
  busy.value = true
  try {
    await api.block(p.value.ip || p.value.src_ip)
    toast('已加入黑名单', p.value.ip || p.value.src_ip, 'ok')
    closeDrawer()
  } finally { busy.value = false }
}
async function unblock() {
  busy.value = true
  try {
    await api.unblock(p.value.ip || p.value.src_ip)
    toast('已解除封禁', p.value.ip || p.value.src_ip, 'ok')
    closeDrawer()
  } finally { busy.value = false }
}
</script>

<template>
  <div class="overlay" :class="{ show: drawer.open }" @click="closeDrawer()"></div>
  <aside class="drawer" :class="{ show: drawer.open }">
    <div class="drawer-head">
      <strong style="font-size: 14px">{{ drawer.title }}</strong>
      <div class="spacer" style="flex: 1"></div>
      <button class="icon-btn" @click="closeDrawer()">×</button>
    </div>
    <div class="drawer-body">
      <template v-if="kind === 'ip'">
        <div class="spread">
          <div>
            <div class="mono strong" style="font-size: 20px">{{ p.ip || p.src_ip }}</div>
            <div class="muted" style="font-size: 12px; margin-top: 3px">最近观测 {{ p.last ? fmtAgo(p.last) : '刚刚' }}</div>
          </div>
          <div class="row"><TagPill :text="trust.label" :kind="trust.kind" dot /></div>
        </div>
        <div class="detail-grid" style="margin-top: 16px">
          <div class="detail-cell"><div class="dc-label">命中次数</div><div class="dc-value">{{ fmtInt(p.count || p.hits || 0) }}</div></div>
          <div class="detail-cell"><div class="dc-label">首次观测</div><div class="dc-value" style="font-size: 12.5px">{{ fmtDateTime(p.created_ns || Date.now() * 1e6) }}</div></div>
          <div class="detail-cell"><div class="dc-label">主要协议</div><div class="dc-value">{{ p.protocol || 'TCP' }}</div></div>
          <div class="detail-cell"><div class="dc-label">主要目的端口</div><div class="dc-value">{{ p.dst_port || 80 }}</div></div>
        </div>
        <div class="panel" style="margin-top: 16px">
          <div class="panel-head"><div class="panel-title">最近事件</div></div>
          <div class="timeline" style="padding: 14px 16px">
            <div v-for="e in recent" :key="e.id" class="timeline-item" :class="e.action === 'DROP' ? 'danger' : 'ok'">
              <div class="timeline-time">{{ fmtDateTime(e.timestamp_ns) }}</div>
              <div class="timeline-text">{{ e.action }} · {{ e.reason }} · {{ e.protocol }}/{{ e.dst_port }}</div>
            </div>
            <div v-if="!recent.length" class="muted">暂无采样事件</div>
          </div>
        </div>
      </template>

      <template v-else-if="kind === 'event' || kind === 'packet'">
        <div class="detail-grid">
          <div class="detail-cell"><div class="dc-label">源地址</div><div class="dc-value mono">{{ p.src_ip }}:{{ p.src_port }}</div></div>
          <div class="detail-cell"><div class="dc-label">目的地址</div><div class="dc-value mono">{{ p.dst_ip }}:{{ p.dst_port }}</div></div>
          <div class="detail-cell"><div class="dc-label">协议</div><div class="dc-value">{{ p.protocol }}</div></div>
          <div class="detail-cell"><div class="dc-label">动作</div><div class="dc-value">{{ p.action }}</div></div>
          <div class="detail-cell"><div class="dc-label">命中规则</div><div class="dc-value">{{ p.rule || p.action }}</div></div>
          <div class="detail-cell"><div class="dc-label">包长</div><div class="dc-value">{{ p.length }} B</div></div>
        </div>
        <div style="margin-top: 16px" class="field-label">原因</div>
        <div class="code-block" style="margin-top: 6px">{{ p.reason || '—' }}</div>
        <div style="margin-top: 14px" class="field-label">原始字段</div>
        <div class="code-block" style="margin-top: 6px">{{ JSON.stringify(p, null, 2) }}</div>
      </template>

      <template v-else>
        <dl class="kv">
          <template v-for="(v, k) in p" :key="k">
            <dt>{{ k }}</dt>
            <dd class="mono">{{ typeof v === 'object' ? JSON.stringify(v) : v }}</dd>
          </template>
        </dl>
      </template>
    </div>
    <div v-if="kind === 'ip'" class="drawer-foot">
      <button class="btn btn-danger" :disabled="busy" @click="block()">加入黑名单</button>
      <button class="btn" :disabled="busy" @click="unblock()">解除封禁</button>
    </div>
  </aside>
</template>
