<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { openModal } from '../stores/ui'
import type { L7Pattern } from '../api/types'

const patterns = ref<L7Pattern[]>([])
const probe = ref('GET /api/stats HTTP/1.1')
const saved = ref(false)
const byteLen = (s: string) => new TextEncoder().encode(s).length
const first8 = (s: string) => s.slice(0, 8)

onMounted(async () => { patterns.value = await api.l7Patterns() })

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
  } catch (e) { toast('保存失败', String(e), 'danger') }
}
function remove(i: number) { patterns.value.splice(i, 1) }
</script>

<template>
  <div class="page">
    <div class="grid grid-main-side">
      <PanelCard title="L7 指纹规则" sub="匹配 TCP 载荷前 8 字节，命中即 DROP" flush>
        <template #actions>
          <TagPill :text="`${patterns.length} / 8`" :kind="patterns.length >= 8 ? 'tag-warn' : 'tag-accent'" />
          <button class="btn btn-sm" @click="openModal('新增 L7 指纹', 'l7')">新增</button>
          <button class="btn btn-sm btn-primary" @click="save">保存</button>
        </template>
        <div class="table-wrap">
          <table class="dt">
            <thead><tr><th style="width: 46px">#</th><th>特征串</th><th>掩码</th><th>字节长度</th><th>命中</th><th></th></tr></thead>
            <tbody>
              <tr v-for="(p, i) in patterns" :key="i">
                <td class="muted">{{ i + 1 }}</td>
                <td><input v-model="p.pattern" class="input mono" style="height: 28px" /></td>
                <td><input v-model="p.mask" class="input mono" style="height: 28px" placeholder="全匹配" /></td>
                <td class="mono muted">{{ byteLen(p.pattern) }} B</td>
                <td><TagPill :text="match(p) ? '命中' : '不命中'" :kind="match(p) ? 'tag-danger' : ''" /></td>
                <td class="col-actions"><button class="btn btn-sm btn-ghost" @click="remove(i)">删除</button></td>
              </tr>
              <tr v-if="!patterns.length"><td colspan="6" class="empty"><div class="title">暂无指纹</div>添加后 L7 模块才会扫描载荷</td></tr>
            </tbody>
          </table>
        </div>
      </PanelCard>

      <PanelCard title="在线探测" sub="规则变动后本地预演">
        <div class="field">
          <label class="field-label">载荷样本</label>
          <textarea v-model="probe" class="input mono" rows="4"></textarea>
        </div>
        <div class="code-block" style="margin-top: 12px">{{ JSON.stringify({ bytes: byteLen(probe), first8: first8(probe), saved }, null, 2) }}</div>
        <div class="panel" style="margin-top: 12px">
          <div class="panel-head"><div class="panel-title">匹配结果</div></div>
          <div class="panel-body col" style="gap: 8px">
            <div v-for="(p, i) in patterns" :key="i" class="spread">
              <span class="mono">{{ p.pattern }}</span>
              <TagPill :text="match(p) ? 'DROP' : 'PASS'" :kind="match(p) ? 'tag-danger' : 'tag-ok'" />
            </div>
            <div v-if="!patterns.length" class="muted">无规则</div>
          </div>
        </div>
      </PanelCard>
    </div>
  </div>
</template>
