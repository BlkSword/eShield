<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api, state, setToken } from '../api/client'
import { store, toast } from '../stores/app'
import type { ConfigSnapshot, FragmentPolicy, PortRateLimitConfig, RateLimitBlockMode } from '../api/types'

const cfg = ref<ConfigSnapshot | null>(null)
const webhook = ref('')
const threshold = ref(1000)
const cooldown = ref(60)
const retention = ref(30)
const token = ref(state.token)
const saving = ref(false)

// 「访问控制与分片」独立编辑态：避免直接 v-model 可选嵌套字段导致类型收窄问题。
const portRate = ref<PortRateLimitConfig>({ enabled: true, threshold: 2000, tick_ms: 100 })
const fragmentPolicy = ref<FragmentPolicy>('rate_limit')
const blockMode = ref<RateLimitBlockMode>('hard')

const fragmentHint = computed(() => {
  switch (fragmentPolicy.value) {
    case 'pass': return '放行非首片分片，仅保留源地址级判断（v0.4.x 兼容行为）'
    case 'rate_limit': return '计入 协议 + 目的端口 聚合限速（默认，推荐）'
    case 'drop': return '直接丢弃非首片分片，最严格，可能影响合法分片流量'
    default: return 'pass / rate_limit / drop'
  }
})
const blockModeHint = computed(() =>
  blockMode.value === 'soft'
    ? '只丢弃超限包、不拉黑源 IP，适合 NAT 出口'
    : '超限后把源 IP 加入动态黑名单（默认）',
)

const dangerLevel = computed(() => store.stats?.danger_level || 0)
const dangerLabel = computed(() => ['平稳', '关注', '警戒', '严重'][Math.min(dangerLevel.value, 3)])
const dangerTone = computed(() => (['ok', 'warn', 'warn', 'danger'] as const)[Math.min(dangerLevel.value, 3)])

/** 兼容旧节点：缺失 v0.5.0 字段时补默认值，保证面板可用。 */
function ensureDefaults() {
  if (!cfg.value) return
  if (!cfg.value.port_rate_limit) cfg.value.port_rate_limit = { enabled: true, threshold: 2000, tick_ms: 100 }
  if (!cfg.value.fragment_policy) cfg.value.fragment_policy = 'rate_limit'
  if (!cfg.value.rate_limit_block_mode) cfg.value.rate_limit_block_mode = 'hard'
  portRate.value = { ...cfg.value.port_rate_limit }
  fragmentPolicy.value = cfg.value.fragment_policy
  blockMode.value = cfg.value.rate_limit_block_mode
}
/** 保存后重新拉取运行时快照，让界面显示服务端实际生效值。 */
async function reloadConfig() {
  cfg.value = await api.config()
  ensureDefaults()
}
onMounted(async () => {
  cfg.value = await api.config()
  ensureDefaults()
})
async function save() {
  if (!cfg.value) return
  saving.value = true
  try {
    await api.patchConfig({
      rate_limit_enabled: cfg.value.rate_limit_enabled,
      syn_proxy_enabled: cfg.value.syn_proxy_enabled,
      l7_scan_enabled: cfg.value.l7_scan_enabled,
      udp_flood_enabled: cfg.value.udp_flood_enabled,
      icmp_flood_enabled: cfg.value.icmp_flood_enabled,
      geoip_enabled: cfg.value.geoip_enabled,
      conn_track_enabled: cfg.value.conn_track_enabled,
      tcp_reset_on_drop: cfg.value.tcp_reset_on_drop,
      // v0.5.0：分片策略 / 限速处置模式 / 协议+目的端口聚合限速
      fragment_policy: fragmentPolicy.value,
      rate_limit_block_mode: blockMode.value,
      // 端口聚合限速不使用指数衰减，decay/block 字段按数据面语义取 0/1/0。
      port_rate_limit: {
        enabled: portRate.value.enabled,
        // 输入框被清空时 v-model.number 会得到空串，这里兜底成合法值，避免 PATCH 被拒。
        threshold: Math.max(1, Math.round(Number(portRate.value.threshold) || 2000)),
        tick_ms: Math.max(1, Math.round(Number(portRate.value.tick_ms) || 100)),
        decay_num: 0,
        decay_den: 1,
        block_duration_s: 0,
      },
    })
    toast('系统设置已保存', '运行时参数已下发数据面，部分参数需重载配置后生效', 'ok')
    await reloadConfig()
  } catch (e) {
    const desc = store.role === 'readonly' ? '只读令牌不允许写操作（403）' : String(e)
    toast('保存失败', desc, 'danger')
  } finally {
    saving.value = false
  }
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
      <div class="page-actions">
        <button class="btn btn-primary btn-sm" :disabled="saving" @click="save">
          {{ saving ? '保存中…' : '保存运行参数' }}
        </button>
      </div>
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
            <dt>审计后端</dt>
            <dd class="mono" :title="cfg?.audit_path">
              {{ cfg?.audit_enabled ? '文件审计已启用' : '文件审计未启用' }}
            </dd>
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

    <PanelCard title="访问控制与分片" sub="v0.5.0 · 运行时热生效">
      <div class="setting-row">
        <div class="sr-main">
          <div class="sr-title">端口聚合限速</div>
          <div class="sr-desc">按 协议 + 目的端口 聚合统计，防伪造源 IP 绕过单源限速（默认启用）</div>
        </div>
        <ToggleSwitch v-model="portRate.enabled" />
      </div>
      <div class="grid grid-3" style="margin-top: 12px">
        <div class="field">
          <label class="field-label">聚合限速阈值（包/窗口）</label>
          <input v-model.number="portRate.threshold" class="input mono" type="number" min="1" />
          <div class="field-hint">窗口 {{ portRate.tick_ms || 100 }}ms，默认 2000 包/窗口</div>
        </div>
        <div class="field">
          <label class="field-label">非首片分片策略</label>
          <select v-model="fragmentPolicy" class="select">
            <option value="pass">pass · 放行</option>
            <option value="rate_limit">rate_limit · 计入聚合限速</option>
            <option value="drop">drop · 直接丢弃</option>
          </select>
          <div class="field-hint">{{ fragmentHint }}</div>
        </div>
        <div class="field">
          <label class="field-label">限速超限处置模式</label>
          <select v-model="blockMode" class="select">
            <option value="hard">hard · 拉黑源 IP</option>
            <option value="soft">soft · 只丢弃不拉黑</option>
          </select>
          <div class="field-hint">{{ blockModeHint }}</div>
        </div>
      </div>
      <div class="muted" style="margin-top: 10px; font-size: 11px; line-height: 1.55">
        soft 适合 NAT 出口：超限只丢弃超量包，不把出口 IP 拉黑；pass 为 v0.4.x 兼容行为（跳过 L4 模块，不推荐）。
      </div>
    </PanelCard>

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
