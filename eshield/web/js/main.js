/* 控制台入口：主题、侧边栏、头部态势条、SSE 连接管理、全局快捷键、路由启动。 */
import { $ } from './format.js';
import { icon } from './icons.js';
import { store } from './store.js';
import { apiGet } from './api.js';
import { toast } from './ui.js';
import { refreshAllCharts, resizeAllCharts } from './charts.js';
import { registerPage, startRouter, navigate } from './router.js';
import { openIpDrawer } from './ipdrawer.js';

import * as overview from './pages/overview.js';
import * as attacks from './pages/attacks.js';
import * as packets from './pages/packets.js';
import * as audit from './pages/audit.js';
import * as policy from './pages/policy.js';
import * as rules from './pages/rules.js';
import * as security from './pages/security.js';
import * as cluster from './pages/cluster.js';
import * as settings from './pages/settings.js';

/* ================= 主题 ================= */
const rootEl = document.documentElement;
function applyTheme(t) {
  rootEl.setAttribute('data-theme', t);
  localStorage.setItem('eshield-theme', t);
  store.set('theme', t);
}
applyTheme(localStorage.getItem('eshield-theme') || 'dark');
$('#themeBtn').addEventListener('click', () => {
  applyTheme(rootEl.getAttribute('data-theme') === 'dark' ? 'light' : 'dark');
  refreshAllCharts();
});

/* ================= 侧边栏 ================= */
const NAV = [
  { group: '监控', items: [
    { id: 'overview', label: '总览', icon: 'dashboard' },
    { id: 'attacks', label: '攻击事件', icon: 'zap' },
    { id: 'packets', label: '包日志', icon: 'terminal' },
    { id: 'audit', label: '审计日志', icon: 'fileText' },
  ]},
  { group: '防护', items: [
    { id: 'policy', label: '防护策略', icon: 'shield' },
    { id: 'rules', label: '规则中心', icon: 'listChecks' },
    { id: 'security', label: '安全运营', icon: 'crosshair' },
  ]},
  { group: '系统', items: [
    { id: 'cluster', label: '集群节点', icon: 'network' },
    { id: 'settings', label: '设置', icon: 'settings' },
  ]},
];
$('#logoMark').innerHTML = icon('shieldCheck', 20);
$('#nav').innerHTML = NAV.map(g => `
  <div class="nav-group-label">${g.group}</div>
  ${g.items.map(it => `<button class="nav-item" data-nav="${it.id}">${icon(it.icon)}<span class="nav-label">${it.label}</span></button>`).join('')}
`).join('');
$('#nav').addEventListener('click', e => {
  const btn = e.target.closest('[data-nav]');
  if (btn) navigate(btn.dataset.nav);
});
$('#collapseBtn').addEventListener('click', () => {
  $('#sidebar').classList.toggle('collapsed');
  setTimeout(resizeAllCharts, 280);
});
$('#versionText').textContent = 'v' + (window.__INITIAL_CONFIG__?.version || '?');

/* ================= 页面注册 ================= */
for (const mod of [overview, attacks, packets, audit, policy, rules, security, cluster, settings]) {
  registerPage(mod.id, mod);
}

/* ================= 危险等级 & 顶部态势 ================= */
const DANGER_LEVELS = [
  { cls: '', text: '危险等级 L0 · 平稳' },
  { cls: 'l1', text: '危险等级 L1 · 警戒' },
  { cls: 'l2', text: '危险等级 L2 · 危险' },
];
function renderDanger(level) {
  const lv = DANGER_LEVELS[Math.min(level, 2)];
  const pill = $('#dangerPill');
  pill.className = 'danger-pill ' + lv.cls;
  $('#dangerText').textContent = lv.text;
  $('#xdpMeta').textContent = level > 0
    ? `${cfg?.interface || '—'} · 防御等级已上调`
    : `${cfg?.interface || '—'} · DRV_MODE`;
}

let cfg = window.__INITIAL_CONFIG__ || {};

async function pollStats() {
  try {
    const stats = await apiGet('/api/stats');
    store.set('stats', stats);
    renderDanger(stats.danger_level || 0);
    $('#hdrPps').textContent = fmtPps(stats.current_pps);
    $('#hdrDps').textContent = fmtPps(stats.current_dps);
    $('#hdrDps').classList.toggle('hot', (stats.current_dps || 0) > 20000);
  } catch { /* 网络抖动时保持旧状态 */ }
}

/* 头部 PPS 格式化：≥1 万显示 X.Xk */
function fmtPps(n) {
  n = Number(n || 0);
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}

apiGet('/api/config').then(c => {
  cfg = c;
  $('#xdpMeta').textContent = `${c.interface || '—'} · DRV_MODE`;
  $('#xdpName').textContent = 'XDP 程序已挂载';
}).catch(() => {});
pollStats();
setInterval(pollStats, 5000);

/* SSE：审计事件流，全局单连接，页面通过 store.on('audit') 订阅 */
function renderSse(status) {
  const dot = $('#sseDot'), label = $('#sseLabel');
  dot.className = 'live-dot' + (status === 'connected' ? ' on' : status === 'error' ? ' err' : '');
  label.textContent = status === 'connected' ? '实时' : status === 'error' ? '重连中' : '连接中';
}
store.on('sse', renderSse);
function connectSse() {
  store.set('sse', 'connecting');
  const es = new EventSource('/api/audit/stream');
  es.onopen = () => store.set('sse', 'connected');
  es.onerror = () => store.set('sse', 'error');
  es.addEventListener('audit', e => {
    try { store.emit('audit', JSON.parse(e.data)); } catch { /* 忽略坏帧 */ }
  });
}
renderSse('connecting');
connectSse();

/* ================= 全局搜索 / 快捷键 ================= */
document.addEventListener('keydown', e => {
  if (e.key === '/' && document.activeElement !== $('#globalSearch')
      && !['INPUT', 'TEXTAREA', 'SELECT'].includes(document.activeElement?.tagName)) {
    e.preventDefault();
    $('#globalSearch').focus();
  }
});
$('#globalSearch').addEventListener('keydown', e => {
  if (e.key !== 'Enter') return;
  const v = e.target.value.trim();
  if (!v) return;
  openIpDrawer(v);
  e.target.blur();
});

/* ================= 启动 ================= */
window.addEventListener('resize', resizeAllCharts);
startRouter();

/* 供页面使用的共享操作 */
export { openIpDrawer, toast };
