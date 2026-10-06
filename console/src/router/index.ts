import { createRouter, createWebHashHistory, type RouteRecordRaw } from 'vue-router'
import OverviewView from '../views/OverviewView.vue'

// Hash history keeps the whole console inside a single embedded HTML file.
export const navGroups: { label: string; items: { path: string; label: string; glyph: string }[] }[] = [
  {
    label: '监控',
    items: [
      { path: '/overview', label: '总览', glyph: '◧' },
      { path: '/attacks', label: '攻击事件', glyph: '⚑' },
      { path: '/packets', label: '包日志', glyph: '≡' },
      { path: '/audit', label: '审计日志', glyph: '▤' },
    ],
  },
  {
    label: '防护',
    items: [
      { path: '/modules', label: '防护模块', glyph: '◈' },
      { path: '/access', label: '访问控制', glyph: '⇄' },
      { path: '/l7', label: 'L7 指纹', glyph: '⌁' },
      { path: '/projects', label: '防护项目', glyph: '▣' },
    ],
  },
  {
    label: '策略',
    items: [
      { path: '/geoip', label: 'GeoIP 与情报', glyph: '◍' },
      { path: '/rules', label: '规则与 Hub', glyph: '⛓' },
    ],
  },
  {
    label: '系统',
    items: [{ path: '/settings', label: '系统设置', glyph: '⚙' }],
  },
]

const routes: RouteRecordRaw[] = [
  { path: '/', redirect: '/overview' },
  { path: '/overview', component: OverviewView, meta: { title: '总览', sub: '实时流量与防护状态' } },
  { path: '/attacks', component: () => import('../views/AttacksView.vue'), meta: { title: '攻击事件', sub: 'DROP / PASS 事件明细' } },
  { path: '/packets', component: () => import('../views/PacketsView.vue'), meta: { title: '包日志', sub: 'RingBuf 采样数据包' } },
  { path: '/audit', component: () => import('../views/AuditView.vue'), meta: { title: '审计日志', sub: '控制面操作记录' } },
  { path: '/modules', component: () => import('../views/ModulesView.vue'), meta: { title: '防护模块', sub: '逐模块启停与参数' } },
  { path: '/access', component: () => import('../views/AccessView.vue'), meta: { title: '访问控制', sub: '黑名单 / 白名单 / 端口 ACL' } },
  { path: '/l7', component: () => import('../views/L7View.vue'), meta: { title: 'L7 指纹', sub: 'TCP 载荷前 8 字节匹配' } },
  { path: '/projects', component: () => import('../views/ProjectsView.vue'), meta: { title: '防护项目', sub: '按目标与端口编排模块' } },
  { path: '/geoip', component: () => import('../views/GeoIpView.vue'), meta: { title: 'GeoIP 与情报', sub: '国家 / ASN / 威胁源' } },
  { path: '/rules', component: () => import('../views/RulesView.vue'), meta: { title: '规则与 Hub', sub: '规则包与节点同步' } },
  { path: '/settings', component: () => import('../views/SettingsView.vue'), meta: { title: '系统设置', sub: '运行参数与告警' } },
  { path: '/login', component: () => import('../views/LoginView.vue'), meta: { title: '登录', public: true } },
]

export const router = createRouter({ history: createWebHashHistory(), routes })
