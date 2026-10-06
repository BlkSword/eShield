<script setup lang="ts">
import { onMounted, ref } from 'vue'
import PanelCard from '../components/PanelCard.vue'
import TagPill from '../components/TagPill.vue'
import ToggleSwitch from '../components/ToggleSwitch.vue'
import { api } from '../api/client'
import { toast } from '../stores/app'
import { threatFeeds } from '../api/mock'
import { fmtInt } from '../utils/format'

const enabled = ref(false)
const defaultAction = ref<'pass' | 'drop'>('pass')
const countries = ref('CN, SG')
const allowCountries = ref('')
const asns = ref('')
const csvPath = ref('/etc/eshield/geoip.csv')
const loading = ref(false)

onMounted(async () => {
  const cfg = await api.config()
  enabled.value = !!cfg.geoip_enabled
  defaultAction.value = cfg.geoip_default_action === 1 ? 'drop' : 'pass'
  const g = (cfg as any).geoip || {}
  countries.value = (g.block_countries || []).join(', ')
  allowCountries.value = (g.allow_countries || []).join(', ')
  asns.value = (g.block_asns || []).join(', ')
  if (g.country_blocks_csv) csvPath.value = g.country_blocks_csv
})
async function save() {
  loading.value = true
  try {
    await api.patchConfig({
      geoip_enabled: enabled.value,
      geoip_default_action: defaultAction.value === 'drop' ? 1 : 0,
    })
    toast('GeoIP 策略已保存', enabled.value ? '运行时生效' : '已停用', 'ok')
  } finally { loading.value = false }
}
async function reload() {
  loading.value = true
  try {
    await api.reloadGeoIp()
    toast('GeoIP CSV 已重载', csvPath.value, 'ok')
  } catch (e) {
    toast('重载失败', String(e), 'danger')
  } finally { loading.value = false }
}

async function syncIntel() {
  try {
    await api.syncThreatIntel()
    toast('威胁情报同步已触发', '稍后刷新查看结果', 'ok')
  } catch (e) {
    toast('同步失败', String(e), 'danger')
  }
}
</script>

<template>
  <div class="page">
    <div class="grid grid-main-side">
      <PanelCard title="GeoIP / ASN 策略" sub="按国家/地区或 ASN 决定放行或阻断">
        <template #actions>
          <ToggleSwitch v-model="enabled" />
          <button class="btn btn-sm" :disabled="loading" @click="reload">重载 CSV</button>
          <button class="btn btn-sm btn-primary" @click="save">保存</button>
        </template>
        <div class="setting-row">
          <div class="sr-main"><div class="sr-title">默认动作</div><div class="sr-desc">未命中 allow 列表时的行为；allow 为空且默认 drop 会拦截所有非白名单流量</div></div>
          <div class="segmented">
            <button :class="{ active: defaultAction === 'pass' }" @click="defaultAction = 'pass'">PASS</button>
            <button :class="{ active: defaultAction === 'drop' }" @click="defaultAction = 'drop'">DROP</button>
          </div>
        </div>
        <div class="grid grid-2" style="margin-top: 4px">
          <div class="field"><label class="field-label">阻断国家/地区（ISO 代码，逗号分隔）</label><input v-model="countries" class="input mono" placeholder="RU, KP" /></div>
          <div class="field"><label class="field-label">放行国家/地区（默认 drop 时生效）</label><input v-model="allowCountries" class="input mono" placeholder="CN, SG" /></div>
          <div class="field"><label class="field-label">阻断 ASN</label><input v-model="asns" class="input mono" placeholder="4134, 4837" /></div>
          <div class="field"><label class="field-label">国家 CSV 路径</label><input v-model="csvPath" class="input mono" /></div>
        </div>
        <div class="panel-body muted" style="font-size: 12px; padding: 12px 0 0">
          CSV 格式：<span class="mono">network,country_iso</span>，支持 IPv4/IPv6 CIDR；最多写入 4096 条 LPM 表项，超出后按文件顺序截断。
        </div>
      </PanelCard>

      <PanelCard title="地理分布" sub="按来源国家聚合（演示数据）">
        <div class="col" style="gap: 10px">
          <div v-for="c in [{ n: 'CN', v: 62 }, { n: 'US', v: 18 }, { n: 'RU', v: 9 }, { n: 'SG', v: 6 }, { n: 'OTHER', v: 5 }]" :key="c.n">
            <div class="spread" style="font-size: 12.5px"><span class="mono">{{ c.n }}</span><span class="muted">{{ c.v }}%</span></div>
            <div class="progress" style="margin-top: 5px"><i :style="{ width: c.v + '%' }"></i></div>
          </div>
        </div>
      </PanelCard>
    </div>

    <PanelCard title="威胁情报源" sub="定时拉取并写入动态黑名单" flush>
      <template #actions><button class="btn btn-sm" @click="syncIntel()">立即同步</button></template>
      <div class="table-wrap">
        <table class="dt">
          <thead><tr><th>名称</th><th>地址</th><th>间隔</th><th class="col-num">置信度</th><th class="col-num">条目数</th><th>最近同步</th><th>状态</th></tr></thead>
          <tbody>
            <tr v-for="f in threatFeeds" :key="f.name">
              <td class="cell-main">{{ f.name }}</td>
              <td class="mono muted" style="max-width: 340px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap">{{ f.url }}</td>
              <td>{{ f.interval }}</td>
              <td class="col-num mono">{{ f.confidence }}</td>
              <td class="col-num mono">{{ fmtInt(f.entries) }}</td>
              <td class="muted">{{ f.last }}</td>
              <td><TagPill text="正常" kind="tag-ok" dot /></td>
            </tr>
          </tbody>
        </table>
      </div>
    </PanelCard>
  </div>
</template>
