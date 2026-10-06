<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
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

onMounted(async () => { cfg.value = await api.config() })
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
    <div class="grid grid-2">
      <PanelCard title="运行参数" sub="开关类参数热生效；监听地址等需重启">
        <template #actions><button class="btn btn-sm btn-primary" @click="save">保存</button></template>
        <div class="col" style="gap: 0">
          <div class="setting-row"><div class="sr-main"><div class="sr-title">全局速率限制</div><div class="sr-desc">单源超阈值后写入黑名单</div></div><ToggleSwitch v-if="cfg" v-model="cfg.rate_limit_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">SYN Proxy / Cookie</div><div class="sr-desc">IPv4 SYN Flood 缓解</div></div><ToggleSwitch v-if="cfg" v-model="cfg.syn_proxy_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">L7 指纹扫描</div><div class="sr-desc">扫描 TCP 载荷前 8 字节</div></div><ToggleSwitch v-if="cfg" v-model="cfg.l7_scan_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">UDP Flood</div><div class="sr-desc">单源 UDP 速率限制</div></div><ToggleSwitch v-if="cfg" v-model="cfg.udp_flood_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">ICMP Flood</div><div class="sr-desc">单源 ICMP 速率限制</div></div><ToggleSwitch v-if="cfg" v-model="cfg.icmp_flood_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">连接跟踪</div><div class="sr-desc">半连接数超限丢弃新 SYN</div></div><ToggleSwitch v-if="cfg" v-model="cfg.conn_track_enabled" /></div>
          <div class="setting-row"><div class="sr-main"><div class="sr-title">DROP 时发送 TCP RST</div><div class="sr-desc">对 TCP 连接快速断开</div></div><ToggleSwitch v-if="cfg" v-model="cfg.tcp_reset_on_drop" /></div>
        </div>
      </PanelCard>

      <div class="grid" style="gap: 14px">
        <PanelCard title="实例信息" sub="只读">
          <dl class="kv">
            <dt>版本</dt><dd class="mono">v{{ cfg?.version || '0.4.6' }}</dd>
            <dt>网卡</dt><dd class="mono">{{ cfg?.interface }}</dd>
            <dt>监听地址</dt><dd class="mono">{{ cfg?.web_bind }}</dd>
            <dt>存储路径</dt><dd class="mono">{{ cfg?.store_path }}</dd>
            <dt>XDP 模式</dt><dd class="mono">native (DRV)</dd>
          </dl>
        </PanelCard>
        <PanelCard title="访问令牌" sub="控制台与 API 共用">
          <div class="field"><label class="field-label">当前令牌</label><input class="input mono" :value="token" readonly /></div>
          <div class="row" style="margin-top: 12px">
            <button class="btn" @click="resetToken">重置令牌</button>
            <TagPill text="重置后需重新登录" kind="tag-warn" />
          </div>
        </PanelCard>
      </div>
    </div>

    <div class="grid grid-2">
      <PanelCard title="告警" sub="DROP 速率超过阈值时推送">
        <div class="grid grid-2">
          <div class="field"><label class="field-label">Webhook 地址</label><input v-model="webhook" class="input mono" placeholder="https://open.feishu.cn/..." /></div>
          <div class="field"><label class="field-label">触发阈值（DROP/s）</label><input v-model.number="threshold" class="input mono" type="number" /></div>
          <div class="field"><label class="field-label">冷却时间（s）</label><input v-model.number="cooldown" class="input mono" type="number" /></div>
          <div class="field"><label class="field-label">时序保留（天）</label><input v-model.number="retention" class="input mono" type="number" /></div>
        </div>
      </PanelCard>
      <PanelCard title="危险信号" sub="综合 PPS、DROP 率与信任分布">
        <div class="spread">
          <div>
            <div class="muted" style="font-size: 12px">当前危险等级</div>
            <div style="font-size: 30px; font-weight: 700">L{{ store.stats?.danger_level || 0 }}</div>
          </div>
          <TagPill :text="['平稳', '关注', '警戒', '严重'][Math.min(store.stats?.danger_level || 0, 3)]" kind="tag-warn" />
        </div>
        <div class="progress warn" style="margin-top: 12px"><i :style="{ width: `${((store.stats?.danger_level || 0) / 3) * 100}%` }"></i></div>
        <div class="grid grid-4" style="margin-top: 14px">
          <div><div class="muted" style="font-size: 11px">可信</div><div class="mono strong">{{ store.stats?.trust_trusted || 0 }}</div></div>
          <div><div class="muted" style="font-size: 11px">中性</div><div class="mono strong">{{ store.stats?.trust_neutral || 0 }}</div></div>
          <div><div class="muted" style="font-size: 11px">可疑</div><div class="mono strong">{{ store.stats?.trust_suspicious || 0 }}</div></div>
          <div><div class="muted" style="font-size: 11px">恶意</div><div class="mono strong">{{ store.stats?.trust_malicious || 0 }}</div></div>
        </div>
      </PanelCard>
    </div>
  </div>
</template>
