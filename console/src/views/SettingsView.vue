<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api, state, setToken } from '../api/client'
import { store, toast } from '../stores/app'
import type { ConfigSnapshot } from '../api/types'

const cfg = ref<ConfigSnapshot | null>(null)
const webhook = ref('')
const threshold = ref(1000)
const cooldown = ref(60)
const retention = ref(30)
const token = ref(state.token)

const dangerLevel = computed(() => store.stats?.danger_level || 0)
const dangerLabel = computed(() => ['平稳', '关注', '警戒', '严重'][Math.min(dangerLevel.value, 3)])
const dangerTone = computed(() => (['ok', 'warn', 'warn', 'danger'] as const)[Math.min(dangerLevel.value, 3)])

onMounted(async () => {
  cfg.value = await api.config()
})
async function save() {
  if (!cfg.value) return
  await api.patchConfig({
    rate_limit_enabled: cfg.value.rate_limit_enabled,
    syn_proxy_enabled: cfg.value.syn_proxy_enabled,
    l7_scan_enabled: cfg.value.l7_scan_enabled,
    udp_flood_enabled: cfg.value.udp_flood_enabled,
    icmp_flood_enabled: cfg.value.icmp_flood_enabled,
    geoip_enabled: cfg.value.geoip_enabled,
    conn_track_enabled: cfg.value.conn_track_enabled,
    tcp_reset_on_drop: cfg.value.tcp_reset_on_drop,
  })
  toast('系统设置已保存', '部分参数需重载配置后生效', 'ok')
}
function resetToken() {
  const t = Array.from(crypto.getRandomValues(new Uint8Array(16))).map((b) => b.toString(16).padStart(2, '0')).join('')
  token.value = t
  setToken(t)
  toast('访问令牌已重置', '请同步更新所有调用方', 'warn')
}
</script>

<template>
  <div class="page">
    <div class="page-head">
      <div class="page-title">系统设置</div>
      <div class="page-meta">开关类参数热生效；监听地址、存储路径等需重启进程</div>
      <div class="page-actions"><button class="btn btn-primary btn-sm" @click="save">保存运行参数</button></div>
    </div>

    <div class="grid grid-main-side">
      <PanelCard title="运行参数" sub="写入数据面运行时配置">
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">全局速率限制</div><div class="sr-desc">单源超过阈值后写入黑名单</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.rate_limit_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">SYN Proxy / Cookie</div><div class="sr-desc">IPv4 SYN Flood 缓解（实验特性，默认关闭）</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.syn_proxy_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">L7 指纹扫描</div><div class="sr-desc">扫描 TCP 载荷前 8 字节</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.l7_scan_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">UDP Flood</div><div class="sr-desc">单源 UDP 速率限制</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.udp_flood_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">ICMP Flood</div><div class="sr-desc">单源 ICMP 速率限制</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.icmp_flood_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">连接跟踪</div><div class="sr-desc">半连接数超限丢弃新 SYN</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.conn_track_enabled" />
        </div>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">DROP 时发送 TCP RST</div><div class="sr-desc">对 TCP 连接快速断开</div></div>
          <ToggleSwitch v-if="cfg" v-model="cfg.tcp_reset_on_drop" />
        </div>
      </PanelCard>

      <div class="grid" style="grid-template-columns: minmax(0, 1fr); gap: 14px">
        <PanelCard title="实例信息" sub="只读">
          <dl class="kv">
            <dt>版本</dt><dd class="mono">v{{ cfg?.version || '—' }}</dd>
            <dt>网卡</dt><dd class="mono">{{ cfg?.interface || '—' }}</dd>
            <dt>监听地址</dt><dd class="mono">{{ cfg?.web_bind || '—' }}</dd>
            <dt>存储路径</dt><dd class="mono" :title="cfg?.store_path">{{ cfg?.store_path || '—' }}</dd>
            <dt>XDP 模式</dt><dd class="mono">{{ (store.stats as never as Record<string, unknown>)?.xdp_mode || '—' }}</dd>
          </dl>
        </PanelCard>
        <PanelCard title="访问令牌" sub="控制台与 API 共用">
          <div class="field">
            <label class="field-label">当前令牌（仅本次会话内存）</label>
            <input class="input mono" :value="token || '（由 HttpOnly Cookie 管理）'" readonly />
          </div>
          <div class="row" style="margin-top: 10px">
            <button class="btn" @click="resetToken">重置令牌</button>
            <span class="muted" style="font-size: 11px">重置后需重新登录</span>
          </div>
        </PanelCard>
      </div>
    </div>

    <div class="grid grid-2">
      <PanelCard title="告警" sub="DROP 速率超过阈值时推送 Webhook">
        <div class="grid grid-2">
          <div class="field"><label class="field-label">Webhook 地址</label><input v-model="webhook" class="input mono" placeholder="https://open.feishu.cn/..." /></div>
          <div class="field"><label class="field-label">触发阈值（DROP/s）</label><input v-model.number="threshold" class="input mono" type="number" /></div>
          <div class="field"><label class="field-label">冷却时间（s）</label><input v-model.number="cooldown" class="input mono" type="number" /></div>
          <div class="field"><label class="field-label">时序保留（天）</label><input v-model.number="retention" class="input mono" type="number" /></div>
        </div>
        <div class="panel-note" style="border-top: 0; padding: 10px 0 0">
          告警参数写入配置文件后由服务端后台任务读取，控制台仅作展示与预留。
        </div>
      </PanelCard>

      <PanelCard title="危险信号" sub="综合 PPS、DROP 率与信任分布">
        <div class="spread" style="align-items: baseline">
          <div>
            <div class="muted" style="font-size: 11px">当前危险等级</div>
            <div class="mono" style="font-size: 26px; font-weight: 600; line-height: 1.2">L{{ dangerLevel }}</div>
          </div>
          <span class="state" :class="dangerTone === 'ok' ? 'ok' : dangerTone === 'danger' ? 'danger' : 'warn'">
            <span class="dot" :class="dangerTone"></span>{{ dangerLabel }}
          </span>
        </div>
        <div class="progress" :class="dangerTone === 'danger' ? 'danger' : dangerTone === 'warn' ? 'warn' : 'ok'" style="margin-top: 10px">
          <i :style="{ width: ((dangerLevel / 3) * 100) + '%' }"></i>
        </div>
        <div class="dl" style="margin-top: 10px">
          <div class="dl-row"><span class="dl-key">可信来源</span><span class="dl-val">{{ store.stats?.trust_trusted || 0 }}</span></div>
          <div class="dl-row"><span class="dl-key">中性来源</span><span class="dl-val">{{ store.stats?.trust_neutral || 0 }}</span></div>
          <div class="dl-row"><span class="dl-key">可疑来源</span><span class="dl-val">{{ store.stats?.trust_suspicious || 0 }}</span></div>
          <div class="dl-row"><span class="dl-key">恶意来源</span><span class="dl-val">{{ store.stats?.trust_malicious || 0 }}</span></div>
        </div>
      </PanelCard>
    </div>
  </div>
</template>
