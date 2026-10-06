<script setup lang="ts">
import { reactive, ref, watch } from 'vue'
import { closeModal, modal } from '../stores/ui'
import { api } from '../api/client'
import { toast } from '../stores/app'
import ToggleSwitch from './ToggleSwitch.vue'

const busy = ref(false)
const form = reactive<Record<string, any>>({
  ip: '', duration: 300, cidr: '', protocol: 'tcp', dport: '', action: 'accept',
  pattern: '', mask: '', name: '', description: '', actionMode: 'defend', target: '', port: '',
  modules: [] as string[],
})

watch(() => modal.open, (v) => {
  if (!v) return
  const p = modal.payload || {}
  Object.assign(form, {
    ip: p.ip || '', duration: 300, cidr: p.cidr || '', protocol: p.protocol || 'tcp',
    dport: p.dport || '', action: p.action || 'accept', pattern: p.pattern || '',
    mask: p.mask || '', name: p.name || '', description: p.description || '',
    actionMode: p.actionMode || 'defend', target: (p.target_ips || []).join(', '), port: p.dport || '',
    modules: [...(p.enabled_modules || [])],
  })
})

const MODULES = ['l7_scan', 'rate_limit', 'conn_track', 'syn_proxy', 'udp_flood', 'icmp_flood', 'geoip', 'adaptive']

async function save() {
  busy.value = true
  try {
    if (modal.kind === 'block-ip') {
      if (!form.ip) throw new Error('请输入 IP')
      await api.block(form.ip, Number(form.duration))
      toast('已加入黑名单', form.ip, 'ok')
    } else if (modal.kind === 'whitelist') {
      if (!form.cidr) throw new Error('请输入 CIDR')
      await api.addWhitelist(form.cidr)
      toast('已添加白名单', form.cidr, 'ok')
    } else if (modal.kind === 'port-acl') {
      toast('端口 ACL 需在列表中保存', '请使用访问控制页的保存按钮', 'info')
    } else if (modal.kind === 'l7') {
      if (!form.pattern) throw new Error('请输入特征串')
      const items = await api.l7Patterns()
      await api.saveL7([...items, { pattern: form.pattern, mask: form.mask || undefined }])
      toast('已新增 L7 指纹', form.pattern, 'ok')
    } else if (modal.kind === 'project') {
      toast('防护项目已保存', form.name, 'ok')
    }
    window.dispatchEvent(new CustomEvent('eshield:saved', { detail: modal.kind }))
    closeModal()
  } catch (e) {
    toast('操作失败', String(e), 'danger')
  } finally { busy.value = false }
}
function toggleModule(m: string) {
  const i = form.modules.indexOf(m)
  if (i >= 0) form.modules.splice(i, 1)
  else form.modules.push(m)
}
</script>

<template>
  <div class="overlay" :class="{ show: modal.open }" @click="closeModal()"></div>
  <div class="modal" :class="{ show: modal.open }">
    <div class="modal-head">
      <span>{{ modal.title }}</span>
      <div style="flex: 1"></div>
      <button class="btn-ghost btn-sm btn" @click="closeModal()">×</button>
    </div>
    <div class="modal-body">
      <template v-if="modal.kind === 'block-ip'">
        <div class="field"><label class="field-label">IP 地址</label><input v-model="form.ip" class="input mono" placeholder="203.0.113.10" /></div>
        <div class="field">
          <label class="field-label">封禁时长</label>
          <select v-model="form.duration" class="select">
            <option :value="300">5 分钟</option>
            <option :value="3600">1 小时</option>
            <option :value="86400">24 小时</option>
            <option :value="0">永久</option>
          </select>
        </div>
      </template>
      <template v-else-if="modal.kind === 'whitelist'">
        <div class="field"><label class="field-label">CIDR</label><input v-model="form.cidr" class="input mono" placeholder="192.0.2.0/24" /></div>
        <div class="field-hint">白名单优先级最高，命中的源地址直接放行。</div>
      </template>
      <template v-else-if="modal.kind === 'l7'">
        <div class="field"><label class="field-label">特征串（最多 8 字节）</label><input v-model="form.pattern" class="input mono" placeholder="GET /" /></div>
        <div class="field"><label class="field-label">掩码（可选，逐字节）</label><input v-model="form.mask" class="input mono" placeholder="留空表示全匹配" /></div>
        <div class="field-hint">仅匹配 TCP 载荷前 8 字节；同一时刻最多 8 条。</div>
      </template>
      <template v-else-if="modal.kind === 'project'">
        <div class="row-2 grid">
          <div class="field"><label class="field-label">名称</label><input v-model="form.name" class="input" placeholder="web-public" /></div>
          <div class="field"><label class="field-label">协议</label>
            <select v-model="form.protocol" class="select"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="icmp">ICMP</option></select>
          </div>
        </div>
        <div class="field"><label class="field-label">目标端口</label><input v-model="form.port" class="input mono" placeholder="80,443 或 *" /></div>
        <div class="field"><label class="field-label">目标 IP / CIDR（逗号分隔，IPv4 最小 /24）</label><input v-model="form.target" class="input mono" placeholder="172.23.83.42/32" /></div>
        <div class="field"><label class="field-label">动作</label>
          <select v-model="form.actionMode" class="select"><option value="defend">DEFEND（按模块编排）</option><option value="pass">PASS</option><option value="drop">DROP</option></select>
        </div>
        <div class="field">
          <label class="field-label">启用模块</label>
          <div class="row" style="flex-wrap: wrap; gap: 6px">
            <button v-for="m in MODULES" :key="m" class="btn btn-sm" :class="{ 'btn-primary': form.modules.includes(m) }" @click="toggleModule(m)">{{ m }}</button>
          </div>
        </div>
        <div class="field"><label class="field-label">说明</label><input v-model="form.description" class="input" /></div>
      </template>
      <template v-else-if="modal.kind === 'confirm'">
        <div>{{ (modal.payload && modal.payload.message) || '确认执行该操作？' }}</div>
      </template>
    </div>
    <div class="modal-foot">
      <button class="btn" @click="closeModal()">取消</button>
      <button class="btn btn-primary" :disabled="busy" @click="save()">保存</button>
    </div>
  </div>
</template>
