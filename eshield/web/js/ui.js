/* UI 原语：toast、骨架屏、空态、错误态、sparkline、countUp、通用抽屉。 */
import { $, esc } from './format.js';
import { icon } from './icons.js';

export function toast(msg, kind = 'ok') {
  const t = document.createElement('div');
  t.className = `toast toast-${kind}`;
  const ic = kind === 'ok' ? 'check' : kind === 'err' ? 'alert' : 'info';
  t.innerHTML = `<span class="t-icon">${icon(ic)}</span><span>${esc(msg)}</span>`;
  $('#toastWrap').appendChild(t);
  setTimeout(() => { t.classList.add('out'); setTimeout(() => t.remove(), 260); }, 3200);
}

export function skeleton(height = 120) {
  return `<div class="skeleton" style="height:${height}px"></div>`;
}

export function emptyState(title = '暂无数据', sub = '', iconName = 'inbox') {
  return `<div class="empty-state">
    <div class="e-icon">${icon(iconName, 28)}</div>
    <div class="e-title">${esc(title)}</div>
    ${sub ? `<div class="e-sub">${esc(sub)}</div>` : ''}
  </div>`;
}

export function errorState(msg = '加载失败') {
  return `<div class="error-state">
    <div>${esc(msg)}</div>
    <button class="btn btn-ghost btn-sm" data-retry>点击重试</button>
  </div>`;
}

/** 手写 SVG sparkline，values 为数字数组。 */
export function sparkline(values, color, { width = 180, height = 36 } = {}) {
  if (!values.length) values = [0, 0];
  const pad = 2;
  const max = Math.max(...values), min = Math.min(...values);
  const pts = values.map((v, i) => [
    (i / (values.length - 1)) * width,
    height - pad - ((v - min) / (max - min || 1)) * (height - pad * 2),
  ]);
  const line = pts.map(p => p.map(n => n.toFixed(1)).join(',')).join(' ');
  const gid = 'g' + Math.random().toString(36).slice(2, 8);
  return `<svg viewBox="0 0 ${width} ${height}" preserveAspectRatio="none">
    <defs><linearGradient id="${gid}" x1="0" y1="0" x2="0" y2="1">
      <stop offset="0" stop-color="${color}" stop-opacity=".28"/><stop offset="1" stop-color="${color}" stop-opacity="0"/>
    </linearGradient></defs>
    <polygon points="0,${height} ${line} ${width},${height}" fill="url(#${gid})"/>
    <polyline points="${line}" fill="none" stroke="${color}" stroke-width="1.5" stroke-linejoin="round" stroke-linecap="round"/>
  </svg>`;
}

export function countUp(el, target, fmt, dur = 800) {
  const t0 = performance.now();
  (function tick(t) {
    const p = Math.min(1, (t - t0) / dur), e = 1 - Math.pow(1 - p, 3);
    el.textContent = fmt(Math.round(target * e));
    if (p < 1) requestAnimationFrame(tick);
  })(t0);
}

/* ============ 通用抽屉 ============
 * openDrawer({ title, bodyHTML, footHTML }) → drawer 元素
 * 关闭：mask 点击 / Esc / [data-drawer-close]
 */
let drawerEscHandler = null;

export function openDrawer({ headHTML = '', bodyHTML = '', footHTML = '', onClose } = {}) {
  const drawer = $('#drawer');
  drawer.innerHTML = `
    <div class="drawer-head">
      <div style="min-width:0">${headHTML}</div>
      <button class="icon-btn drawer-close" data-drawer-close>${icon('x', 15)}</button>
    </div>
    <div class="drawer-body">${bodyHTML}</div>
    ${footHTML ? `<div class="drawer-foot">${footHTML}</div>` : ''}`;
  $('#drawerMask').classList.add('open');
  drawer.classList.add('open');
  drawer._onClose = onClose;
  const close = () => closeDrawer();
  drawer.querySelector('[data-drawer-close]').addEventListener('click', close);
  $('#drawerMask').onclick = close;
  drawerEscHandler = e => { if (e.key === 'Escape') close(); };
  document.addEventListener('keydown', drawerEscHandler);
  return drawer;
}

export function closeDrawer() {
  const drawer = $('#drawer');
  $('#drawerMask').classList.remove('open');
  drawer.classList.remove('open');
  if (drawerEscHandler) { document.removeEventListener('keydown', drawerEscHandler); drawerEscHandler = null; }
  if (typeof drawer._onClose === 'function') {
    try { drawer._onClose(); } catch (e) { console.error('drawer onClose', e); }
    drawer._onClose = null;
  }
}

export const drawerOpen = () => $('#drawer').classList.contains('open');
