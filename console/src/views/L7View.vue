<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openModal } from '../stores/ui'
import type { L7Pattern } from '../api/types'

const patterns = ref<L7Pattern[]>([])
const probe = ref('GET /api/stats HTTP/1.1')
const saved = ref(false)
const byteLen = (s: string) => new TextEncoder().encode(s).length
const first8 = (s: string) => s.slice(0, 8)

onMounted(async () => {
  patterns.value = await api.l7Patterns()
})

function match(p: L7Pattern) {
  if (!p.pattern) return false
  const a = new TextEncoder().encode(probe.value.padEnd(8, '\0')).slice(0, 8)
  const b = new TextEncoder().encode(p.pattern.padEnd(8, '\0')).slice(0, 8)
  const mask = p.mask ? new TextEncoder().encode(p.mask.padEnd(8, '\0')).slice(0, 8) : new Uint8Array(8).fill(0xff)
  for (let i = 0; i < 8; i++) if ((a[i] & mask[i]) !== (b[i] & mask[i])) return false
  return true
}
async function save() {
  try {
    await api.saveL7(patterns.value.filter((p) => p.pattern))
    saved.value = true
    toast('L7 指纹已保存', `${patterns.value.length} 条规则`, 'ok')
    setTimeout(() => (saved.value = false), 1500)
  } catch (e) {
    toast('保存失败', String(e), 'danger')
  }
}
function remove(i: number) {
  patterns.value.splice(i, 1)
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">L7 指纹</div>
      <div class="page-meta">匹配 TCP 载荷前 8 字节，命中即 DROP · 最多 8 条</div>
      <div class="page-actions">
        <span class="state" :class="patterns.length >= 8 ? 'warn' : ''">
          <span class="dot" :class="patterns.length >= 8 ? 'warn' : 'ok'"></span>{{ patterns.length }} / 8
        </span>
        <button class="btn btn-sm" @click="openModal('新增 L7 指纹', 'l7')">新增</button>
        <button class="btn btn-primary btn-sm" @click="save">保存</button>
      </div>
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="指纹规则" sub="特征串与掩码均按字节处理，未填掩码表示全匹配" flush>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th style="width: 46px">#</th><th>特征串</th><th>掩码</th><th class="col-num">字节长度</th><th>在线探测</th><th class="col-actions">操作</th></tr></thead>
            <tbody>
              <tr v-for="(p, i) in patterns" :key="i">
                <td class="muted mono">{{ i + 1 }}</td>
                <td><input v-model="p.pattern" class="input mono" placeholder="GET /" /></td>
                <td><input v-model="p.mask" class="input mono" placeholder="全匹配" /></td>
                <td class="col-num mono muted">{{ byteLen(p.pattern) }} B</td>
                <td>
                  <span class="state" :class="match(p) ? 'danger' : ''">
                    <span class="dot" :class="match(p) ? 'danger' : ''"></span>{{ match(p) ? '命中' : '不命中' }}
                  </span>
                </td>
                <td class="col-actions">
                  <div class="row-actions"><button class="btn btn-sm" @click="remove(i)">删除</button></div>
                </td>
              </tr>
              <tr v-if="!patterns.length"><td colspan="6" class="empty"><div class="title">暂无指纹</div>添加后 L7 模块才会扫描载荷</td></tr>
            </tbody>
          </table>
        </div>
        <div class="panel-note">指纹按「载荷前 8 字节 + 掩码」匹配；数据面最多 8 条，超出部分不生效。</div>
      </PanelCard>

      <PanelCard title="在线探测" sub="规则变动后本地预演，不会下发数据面">
        <div class="field">
          <label class="field-label">载荷样本</label>
          <textarea v-model="probe" class="input mono" rows="5"></textarea>
        </div>
        <div class="detail-grid" style="margin-top: 12px">
          <div class="detail-cell"><div class="dc-label">字节数</div><div class="dc-value mono">{{ byteLen(probe) }}</div></div>
          <div class="detail-cell"><div class="dc-label">前 8 字节</div><div class="dc-value mono">{{ first8(probe) }}</div></div>
        </div>
        <div class="drawer-section" style="margin-top: 14px">
          <h4>匹配结果</h4>
          <div v-for="(p, i) in patterns" :key="i" class="dl-row">
            <span class="mono">{{ p.pattern }}</span>
            <span class="state" :class="match(p) ? 'danger' : 'ok'">
              <span class="dot" :class="match(p) ? 'danger' : 'ok'"></span>{{ match(p) ? 'DROP' : 'PASS' }}
            </span>
          </div>
          <div v-if="!patterns.length" class="muted" style="font-size: 11.5px">无规则</div>
        </div>
        <div class="muted" style="font-size: 11px; margin-top: 12px">
          保存状态：{{ saved ? '已保存' : '未保存' }}
        </div>
      </PanelCard>
    </div>
  </div>
</template>
