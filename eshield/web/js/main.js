/* 控制台入口：文本导航、头部态势、SSE、全局搜索与路由。 */
import { $ } from './format.js';
import { store } from './store.js';
import { apiGet, apiPost } from './api.js';
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

/* ================= 文本导航 ================= */
const NAV = [
  { group: '监控', items: [
    { id: 'overview', label: '总览' },
    { id: 'attacks', label: '攻击事件' },
    { id: 'packets', label: '实时流量' },
    { id: 'audit', label: '审计日志' },
  ]},
  { group: '策略', items: [
    { id: 'policy', label: '防护模块' },
    { id: 'rules', label: '防护规则' },
    { id: 'security', label: '安全运营' },
  ]},
  { group: '系统', items: [
    { id: 'cluster', label: '集群管理' },
    { id: 'settings', label: '系统设置' },
  ]},
];
$('#nav').innerHTML = NAV.map(g => `
  <div class="nav-group-label">${g.group}</div>
  ${g.items.map(it => `<button class="nav-item" data-nav="${it.id}"><span class="nav-label">${it.label}</span></button>`).join('')}
`).join('');
$('#nav').addEventListener('click', e => {
  const btn = e.target.closest('[data-nav]');
  if (btn) navigate(btn.dataset.nav);
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
let cfg = window.__INITIAL_CONFIG__ || {};
function renderDanger(level) {
  const lv = DANGER_LEVELS[Math.min(level, 2)];
  const pill = $('#dangerPill');
  pill.className = 'danger-pill ' + lv.cls;
  $('#dangerText').textContent = lv.text;
  $('#xdpMeta').textContent = level > 0
    ? `${cfg?.interface || '—'} · 防御等级已上调`
    : `${cfg?.interface || '—'} · DRV_MODE`;
}

function fmtPps(n) {
  n = Number(n || 0);
  if (n >= 1e6) return (n / 1e6).toFixed(1) + 'M';
  if (n >= 1e4) return (n / 1e3).toFixed(1) + 'K';
  return String(n);
}
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
apiGet('/api/config').then(c => {
  cfg = c;
  store.set('config', c);
  $('#xdpMeta').textContent = `${c.interface || '—'} · DRV_MODE`;
  $('#xdpName').textContent = 'XDP 程序已挂载';
}).catch(() => {});
pollStats();
setInterval(pollStats, 5000);

/* ================= SSE 审计流 ================= */
function renderSse(status) {
  const label = $('#sseLabel');
  label.textContent = status === 'connected' ? '实时' : status === 'error' ? '重连中' : '连接中';
  label.parentElement.classList.toggle('err', status === 'error');
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

/* ================= 命令面板 ================= */
const COMMANDS = [
  { label: '跳转到 总览', kbd: 'G O', run: () => navigate('overview') },
  { label: '跳转到 攻击事件', kbd: 'G A', run: () => navigate('attacks') },
  { label: '跳转到 实时流量', kbd: 'G T', run: () => navigate('packets') },
  { label: '跳转到 审计日志', kbd: 'G L', run: () => navigate('audit') },
  { label: '跳转到 防护模块', kbd: 'G P', run: () => navigate('policy') },
  { label: '跳转到 防护规则', kbd: 'G R', run: () => navigate('rules') },
  { label: '跳转到 安全运营', kbd: 'G S', run: () => navigate('security') },
  { label: '跳转到 集群管理', kbd: 'G C', run: () => navigate('cluster') },
  { label: '跳转到 系统设置', kbd: 'G ,', run: () => navigate('settings') },
  { label: '聚焦全局搜索', kbd: '/', run: () => $('#globalSearch').focus() },
  { label: '重载配置文件', kbd: 'R', run: async () => {
      try { await apiPost('/api/config/reload'); toast('配置已重载', 'ok'); }
      catch (e) { toast(`重载失败：${e.message}`, 'err'); }
    } },
];
const palette = $('#palette');
const paletteInput = $('#paletteInput');
const paletteList = $('#paletteList');
let paletteItems = COMMANDS.slice();
let paletteIndex = 0;

function renderPalette(filter) {
  const q = (filter || '').trim().toLowerCase();
  paletteItems = COMMANDS.filter(c => !q || c.label.toLowerCase().includes(q));
  paletteIndex = 0;
  paletteList.innerHTML = paletteItems.length
    ? paletteItems.map((c, i) => `<div class="palette-item${i === 0 ? ' active' : ''}" data-index="${i}"><span>${c.label}</span>${c.kbd ? `<span class="kbd">${c.kbd}</span>` : ''}</div>`).join('')
    : '<div class="palette-item">没有匹配的命令</div>';
}
function openPalette() {
  palette.classList.add('show');
  paletteInput.value = '';
  renderPalette('');
  paletteInput.focus();
}
function closePalette() { palette.classList.remove('show'); }
function runPalette(index) {
  const cmd = paletteItems[index];
  if (!cmd) return;
  closePalette();
  Promise.resolve(cmd.run()).catch(() => {});
}
paletteInput.addEventListener('input', () => renderPalette(paletteInput.value));
paletteInput.addEventListener('keydown', e => {
  if (e.key === 'Escape') { closePalette(); return; }
  if (e.key === 'ArrowDown') { e.preventDefault(); paletteIndex = Math.min(paletteIndex + 1, paletteItems.length - 1); }
  if (e.key === 'ArrowUp') { e.preventDefault(); paletteIndex = Math.max(paletteIndex - 1, 0); }
  if (e.key === 'Enter') { e.preventDefault(); runPalette(paletteIndex); return; }
  paletteList.querySelectorAll('.palette-item').forEach((n, i) => n.classList.toggle('active', i === paletteIndex));
});
paletteList.addEventListener('click', e => {
  const item = e.target.closest('[data-index]');
  if (item) runPalette(Number(item.dataset.index));
});
palette.addEventListener('click', e => { if (e.target === palette) closePalette(); });

/* ================= 全局搜索 / 快捷键 ================= */
let gPending = false;
document.addEventListener('keydown', e => {
  if ((e.ctrlKey || e.metaKey) && e.key.toLowerCase() === 'k') {
    e.preventDefault();
    palette.classList.contains('show') ? closePalette() : openPalette();
    return;
  }
  if (e.key === 'Escape' && palette.classList.contains('show')) { closePalette(); return; }
  const tag = document.activeElement?.tagName;
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
  if (gPending) {
    gPending = false;
    const map = { o: 'overview', a: 'attacks', t: 'packets', l: 'audit', p: 'policy', r: 'rules', s: 'security', c: 'cluster', ',': 'settings' };
    if (map[e.key.toLowerCase()]) { e.preventDefault(); navigate(map[e.key.toLowerCase()]); }
    return;
  }
  if (e.key.toLowerCase() === 'g') { gPending = true; setTimeout(() => { gPending = false; }, 1200); return; }
  if (e.key === '/') {
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

/* 跟随系统主题：切换时重绘图表 */
const mq = window.matchMedia('(prefers-color-scheme: light)');
if (mq.addEventListener) mq.addEventListener('change', () => refreshAllCharts());

window.addEventListener('resize', resizeAllCharts);
startRouter();

export { openIpDrawer, toast };
