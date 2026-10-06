<script setup lang="ts">
import { ref } from 'vue'
import { useRouter } from 'vue-router'
import { setToken } from '../api/client'
import { toast } from '../stores/app'

const router = useRouter()
const token = ref('')
const show = ref(false)
const busy = ref(false)
const error = ref('')

async function submit() {
  if (!token.value) { error.value = '请输入访问令牌'; return }
  busy.value = true
  error.value = ''
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token.value }),
    })
    if (!res.ok) throw new Error('令牌无效')
    setToken(token.value)
    toast('登录成功', '欢迎回到 eShield 控制台', 'ok')
    // Move to the protected root so the browser lands on a clean URL.
    window.location.assign('/#/overview')
  } catch {
    // file:// or static preview: fall back to demo mode
    setToken(token.value)
    toast('已进入演示模式', '未连接到 eShield 节点，展示本地样例数据', 'info')
    router.push('/overview')
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-brand">
        <div class="brand-mark" style="width: 38px; height: 38px; font-size: 18px"></div>
        <div>
          <div class="brand-name" style="font-size: 16px">eShield</div>
          <div class="brand-sub">主机防护控制台</div>
        </div>
      </div>
      <div style="font-size: 18px; font-weight: 650; margin-bottom: 4px">登录控制台</div>
      <div class="muted" style="font-size: 12.5px; margin-bottom: 20px">使用节点配置文件中的访问令牌完成认证</div>
      <div class="field">
        <label class="field-label">访问令牌</label>
        <div style="position: relative">
          <input v-model="token" class="input mono" :type="show ? 'text' : 'password'" placeholder="eshield-test" @keyup.enter="submit" />
          <button class="btn btn-sm btn-ghost" style="position: absolute; right: 4px; top: 3px" @click="show = !show">{{ show ? '隐藏' : '显示' }}</button>
        </div>
        <div v-if="error" style="color: var(--danger); font-size: 12px">{{ error }}</div>
      </div>
      <button class="btn btn-primary" style="width: 100%; margin-top: 18px; height: 36px" :disabled="busy" @click="submit">
        {{ busy ? '验证中…' : '进入控制台' }}
      </button>
      <div class="muted" style="font-size: 11.5px; margin-top: 16px; text-align: center">
        令牌存储在浏览器本地，不会上传到第三方
      </div>
    </div>
  </div>
</template>
