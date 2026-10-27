<script setup lang="ts">
import { ref } from 'vue'
import { setToken } from '../api/client'
import { toast } from '../stores/app'

const token = ref('')
const show = ref(false)
const busy = ref(false)
const error = ref('')

async function submit() {
  if (!token.value) {
    error.value = '请输入访问令牌'
    return
  }
  busy.value = true
  error.value = ''
  try {
    const res = await fetch('/api/auth/login', {
      method: 'POST',
      credentials: 'same-origin',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ token: token.value }),
    })
    if (res.status === 401) {
      error.value = '令牌无效，请检查节点配置中的 api_token'
      return
    }
    if (res.status === 429) {
      error.value = '尝试过于频繁，请稍后再试'
      return
    }
    if (!res.ok) {
      error.value = `登录失败（HTTP ${res.status}）`
      return
    }
    // 认证凭据由后端以 HttpOnly Cookie 下发，内存中保留一份供 Bearer 兜底。
    setToken(token.value)
    toast('登录成功', '欢迎回到 eShield 控制台', 'ok')
    window.location.assign('/#/overview')
  } catch {
    // 网络不可达：明确报错，绝不静默切到演示数据 —— 把样例数据当成真实防护状态
    // 会让运维误判节点仍在防护。需要演示数据时请显式使用 ?mock=1 或直接打开离线 HTML。
    error.value = '无法连接 eShield 节点（网络错误），未登录'
  } finally {
    busy.value = false
  }
}
</script>

<template>
  <div class="login-page">
    <div class="login-card">
      <div class="login-brand">
        <div class="brand-mark" style="width: 30px; height: 30px" aria-hidden="true">
          <svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linejoin="round">
            <path d="M12 3 4.5 6v5.5c0 4.2 3.1 7.6 7.5 9.5 4.4-1.9 7.5-5.3 7.5-9.5V6L12 3Z" />
            <path d="M8.8 12.1l2.1 2.1 4.3-4.4" stroke-linecap="round" />
          </svg>
        </div>
        <div>
          <div class="brand-name">eShield</div>
          <div class="brand-sub">主机防护控制台</div>
        </div>
      </div>
      <div style="font-size: 16px; font-weight: 600; margin-bottom: 3px">登录控制台</div>
      <div class="muted" style="font-size: 11.5px; margin-bottom: 18px">
        使用节点配置文件中的 <span class="mono">api_token</span> 完成认证
      </div>

      <div class="field">
        <label class="field-label">访问令牌</label>
        <div class="row" style="gap: 6px">
          <input
            v-model="token"
            class="input mono"
            :type="show ? 'text' : 'password'"
            placeholder="eshield-••••••••"
            @keyup.enter="submit"
          />
          <button class="btn btn-sm" style="flex: none" @click="show = !show">{{ show ? '隐藏' : '显示' }}</button>
        </div>
        <div v-if="error" style="color: var(--danger); font-size: 11.5px; margin-top: 6px">{{ error }}</div>
      </div>

      <button class="btn btn-primary" style="width: 100%; margin-top: 16px; height: 32px" :disabled="busy" @click="submit">
        {{ busy ? '验证中…' : '进入控制台' }}
      </button>

      <div class="muted" style="font-size: 11px; margin-top: 14px; line-height: 1.6">
        凭据以 HttpOnly Cookie 保存，不写入浏览器本地存储；<br />
        本机 CLI 通过 127.0.0.1 访问时免令牌。
      </div>
    </div>
  </div>
</template>
