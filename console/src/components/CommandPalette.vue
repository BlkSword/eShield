<script setup lang="ts">
import { computed, nextTick, ref, watch } from 'vue'
import { useRouter } from 'vue-router'
import { commandOpen, refresh, searchSeed, cycleTheme, toast } from '../stores/app'
import { navGroups } from '../router'
import { openModal } from '../stores/ui'

interface Cmd { id: string; group: string; label: string; hint?: string; run: () => void }
const router = useRouter()
const q = ref('')
const idx = ref(0)
const inputEl = ref<HTMLInputElement | null>(null)

const baseCommands = computed<Cmd[]>(() => {
  const cmds: Cmd[] = []
  for (const g of navGroups) for (const it of g.items) {
    cmds.push({ id: it.path, group: '页面', label: it.label, hint: g.label, run: () => router.push(it.path) })
  }
  cmds.push({ id: 'refresh', group: '操作', label: '刷新统计数据', hint: 'R', run: () => refresh(true) })
  cmds.push({ id: 'theme', group: '操作', label: '切换主题（系统 / 浅色 / 深色）', hint: 'T', run: () => cycleTheme() })
  cmds.push({ id: 'reload', group: '操作', label: '从文件重载配置', hint: '配置', run: () => { toast('配置重载请求已发送', '', 'info') } })
  cmds.push({ id: 'block', group: '操作', label: '封禁 IP…', hint: 'B', run: () => openModal('封禁 IP', 'block-ip') })
  cmds.push({ id: 'whitelist', group: '操作', label: '添加白名单…', hint: 'W', run: () => openModal('添加白名单', 'whitelist') })
  return cmds
})

const commands = computed<Cmd[]>(() => {
  const seed = searchSeed.value.trim()
  const needle = q.value.trim().toLowerCase()
  const list = [...baseCommands.value]
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(seed)) {
    list.unshift({ id: 'block-seed', group: '快捷', label: `封禁 ${seed}`, hint: '回车', run: () => openModal('封禁 IP', 'block-ip', { ip: seed }) })
    list.unshift({ id: 'detail-seed', group: '快捷', label: `查看 ${seed} 详情`, hint: '详情', run: () => router.push('/attacks') })
  }
  if (!needle) return list
  return list.filter((c) => (c.label + c.group + (c.hint || '')).toLowerCase().includes(needle))
})

watch(commandOpen, async (v) => {
  if (!v) return
  q.value = searchSeed.value
  idx.value = 0
  await nextTick()
  inputEl.value?.focus()
})
watch(q, () => { idx.value = 0 })
function pick(c: Cmd | undefined) {
  if (!c) return
  c.run()
  commandOpen.value = false
}
function onKey(e: KeyboardEvent) {
  if (e.key === 'ArrowDown') { e.preventDefault(); idx.value = Math.min(idx.value + 1, commands.value.length - 1) }
  else if (e.key === 'ArrowUp') { e.preventDefault(); idx.value = Math.max(idx.value - 1, 0) }
  else if (e.key === 'Enter') { e.preventDefault(); pick(commands.value[idx.value]) }
  else if (e.key === 'Escape') commandOpen.value = false
}
</script>

<template>
  <div class="overlay" :class="{ show: commandOpen }" @click="commandOpen = false"></div>
  <div class="palette" :class="{ show: commandOpen }">
    <input ref="inputEl" v-model="q" placeholder="搜索页面或执行操作…" @keydown="onKey" />
    <div class="palette-list">
      <template v-for="c in commands" :key="c.id">
        <div class="palette-item" :class="{ active: commands.indexOf(c) === idx }" @click="pick(c)" @mouseenter="idx = commands.indexOf(c)">
          <span>{{ c.label }}</span>
          <span class="k">{{ c.hint }}</span>
        </div>
      </template>
      <div v-if="!commands.length" class="empty" style="padding: 24px">没有匹配的命令</div>
    </div>
  </div>
</template>
