/* 设置：运行信息、智能防御状态、访问令牌、关于。 */
import { apiGet, apiPost, apiPatch, setToken } from '../api.js';
import { $, esc, fmtInt, fmtCn } from '../format.js';
import { toast, skeleton, errorState } from '../ui.js';
import { icon } from '../icons.js';

export const id = 'settings';
export const title = '设置';
export const sub = '运行信息 · 智能防御 · 访问令牌';

const TRUST_SEGS = [
  { key: 'trust_trusted', label: '可信', color: 'var(--success)' },
  { key: 'trust_neutral', label: '中性', color: 'var(--info)' },
  { key: 'trust_suspicious', label: '可疑', color: 'var(--warning)' },
  { key: 'trust_malicious', label: '恶意', color: 'var(--danger)' },
];
const DANGER_TAGS = [
  '<span class="tag tag-pass">L0 · 平稳</span>',
  '<span class="tag tag-limit">L1 · 警戒</span>',
  '<span class="tag tag-drop">L2 · 危险</span>',
];

/** 复制文本：优先 navigator.clipboard，回退 textarea + execCommand */
async function copyText(text) {
  try {
    if (navigator.clipboard?.writeText) {
      await navigator.clipboard.writeText(text);
      return true;
    }
  } catch { /* 走回退路径 */ }
  try {
    const ta = document.createElement('textarea');
    ta.value = text;
    ta.style.position = 'fixed';
    ta.style.opacity = '0';
    document.body.appendChild(ta);
    ta.select();
    const ok = document.execCommand('copy');
    ta.remove();
    return ok;
  } catch { return false; }
}

export function mount(el) {
  el.innerHTML = `
    <div class="settings-grid">
      <div class="card">
        <div class="card-head">
          <div><div class="card-title">运行信息</div><div class="card-sub">当前进程与持久化配置</div></div>
          <div class="card-tools"><button class="btn btn-ghost btn-sm" id="stReload">${icon('refresh', 13)} 重新加载配置</button></div>
        </div>
        <div class="card-body" id="stInfo">${skeleton(180)}</div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><div class="card-title">智能防御状态</div><div class="card-sub">Trust Score 分布与危险等级</div></div>
        </div>
        <div class="card-body" id="stDefense">${skeleton(180)}</div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><div class="card-title">访问令牌</div><div class="card-sub">Web 控制台与 API 认证</div></div>
        </div>
        <div class="card-body">
          <p class="field-hint" style="margin:0 0 12px;line-height:1.6">重置后立即生效，旧令牌失效；SSE 实时流 cookie 已自动更新。</p>
          <button class="btn btn-danger btn-sm" id="stReset">${icon('key', 13)} 重置令牌</button>
          <div id="stTokenOut" class="section-gap"></div>
        </div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><div class="card-title">关于</div><div class="card-sub">版本与许可</div></div>
        </div>
        <div class="card-body" id="stAbout">${skeleton(120)}</div>
      </div>
    </div>`;

  let cfg = null;
  let stats = null;

  /* ================= 运行信息 ================= */
  function renderInfo(c) {
    const kv = [
      ['版本', `v${esc(c.version || '?')}`],
      ['防护网卡', esc(c.interface || '—')],
      ['Web 监听', esc(c.web_bind || `0.0.0.0:${c.web_port || 8720}`)],
      ['日志级别', esc(c.log_level || 'info')],
      ['持久化路径', esc(c.store_path || '—')],
      ['告警 Webhook', c.alert_webhook_url ? '已配置' : '未配置'],
      ['包日志', c.packet_log_enabled ? `已启用 · 每 ${fmtInt(c.packet_log_sample_rate || 1)} 包采样 1 个` : '未启用'],
      ['分布式 Hub', c.hub_enabled ? `已启用 · 节点 ${esc(c.hub_node_name || '—')}` : '未启用'],
    ];
    return `<div class="kv-list">${kv.map(([k, v]) => `<span class="k">${k}</span><span class="v">${v}</span>`).join('')}</div>`;
  }

  /* ================= 智能防御状态 ================= */
  function renderDefense() {
    const total = TRUST_SEGS.reduce((s, x) => s + (stats[x.key] || 0), 0);
    const bar = total ? TRUST_SEGS.map(x => {
      const v = stats[x.key] || 0;
      if (!v) return '';
      return `<div style="width:${(v / total * 100).toFixed(2)}%;background:${x.color}" title="${x.label} ${fmtInt(v)}"></div>`;
    }).join('') : '';
    const lv = Math.min(stats.danger_level || 0, 2);
    return `
      <div style="display:flex;align-items:center;gap:10px;margin-bottom:16px">
        <span class="field-label" style="flex:1">全局危险等级</span>${DANGER_TAGS[lv]}
      </div>
      <div class="field-label" style="margin-bottom:8px">Trust Score 信誉分布 <span class="field-hint">（共 ${fmtCn(total)} 个 IP）</span></div>
      ${total ? `
        <div style="display:flex;height:10px;border-radius:5px;overflow:hidden;background:var(--bg-hover)">${bar}</div>
        <div style="display:flex;gap:14px;flex-wrap:wrap;margin-top:10px;font-size:12px;color:var(--text-2)">
          ${TRUST_SEGS.map(x => `<span style="display:inline-flex;align-items:center;gap:6px"><span style="width:8px;height:8px;border-radius:2px;background:${x.color}"></span>${x.label} ${fmtCn(stats[x.key] || 0)}</span>`).join('')}
        </div>`
        : '<div class="field-hint">暂无 Trust Score 数据</div>'}
      <div class="switch-row section-gap" style="justify-content:space-between;border-top:1px solid var(--border);padding-top:14px;margin-top:16px">
        <div>
          <div class="field-label">内核调试日志（AYA_LOGS）</div>
          <div class="field-hint">输出 eBPF 调试日志，仅排查问题时开启</div>
        </div>
        <label class="switch"><input type="checkbox" id="stEbpfDebug"${cfg?.ebpf_debug_enabled ? ' checked' : ''}><span class="track"></span></label>
      </div>`;
  }

  function renderAbout(c) {
    const version = c?.version || window.__INITIAL_CONFIG__?.version || '?';
    return `<div class="kv-list">
      <span class="k">产品</span><span class="v">eShield — 基于 eBPF/XDP 的主机级网络清洗盾</span>
      <span class="k">版本</span><span class="v">v${esc(version)}</span>
      <span class="k">许可证</span><span class="v">Apache-2.0</span>
      <span class="k">源码仓库</span><span class="v"><a href="https://github.com/eshield/eshield" target="_blank" rel="noopener" style="color:var(--accent)">github.com/eshield/eshield</a></span>
      <span class="k">文档</span><span class="v">详见项目 README 与 docs/ 目录</span>
    </div>`;
  }

  /* ================= 数据加载 ================= */
  async function loadAll() {
    try {
      cfg = await apiGet('/api/config');
      const info = $('#stInfo'); if (info) info.innerHTML = renderInfo(cfg);
      const about = $('#stAbout'); if (about) about.innerHTML = renderAbout(cfg);
      if (stats) { const box = $('#stDefense'); if (box) box.innerHTML = renderDefense(); }
    } catch (e) {
      if (!cfg) {
        const info = $('#stInfo'); if (info) info.innerHTML = errorState(e.message);
        const about = $('#stAbout'); if (about) about.innerHTML = renderAbout(null);
      }
    }
    try {
      stats = await apiGet('/api/stats');
      const box = $('#stDefense'); if (box) box.innerHTML = renderDefense();
    } catch (e) {
      if (!stats) {
        const box = $('#stDefense'); if (box) box.innerHTML = errorState(e.message);
      }
    }
  }

  /* ================= 事件 ================= */
  el.addEventListener('click', async e => {
    if (e.target.closest('[data-retry]')) { loadAll(); return; }

    if (e.target.closest('#stReload')) {
      const btn = $('#stReload');
      btn.disabled = true;
      try {
        const msg = await apiPost('/api/config/reload');
        toast(typeof msg === 'string' ? msg : '配置已重新加载');
        loadAll();
      } catch (err) { toast(err.message, 'err'); }
      finally { btn.disabled = false; }
      return;
    }

    if (e.target.closest('#stReset')) {
      const btn = $('#stReset');
      btn.disabled = true;
      try {
        const data = await apiPost('/api/auth/reset-token');
        const token = data?.token || '';
        setToken(token);
        const out = $('#stTokenOut');
        if (out) {
          out.innerHTML = `
            <div class="token-value" id="stNewToken">${esc(token)}</div>
            <div class="token-box section-gap">
              <button class="btn btn-ghost btn-sm" id="stCopy">${icon('copy', 13)} 复制令牌</button>
              <span class="field-hint">新令牌已生效，请立即保存</span>
            </div>`;
        }
        toast('令牌已重置');
      } catch (err) { toast(err.message, 'err'); }
      finally { btn.disabled = false; }
      return;
    }

    if (e.target.closest('#stCopy')) {
      const token = $('#stNewToken')?.textContent || '';
      if (!token) return;
      const ok = await copyText(token);
      toast(ok ? '已复制到剪贴板' : '复制失败，请手动选择复制', ok ? 'ok' : 'err');
    }
  });

  /* ebpf_debug_enabled 开关（事件委托，渲染后元素会重建） */
  el.addEventListener('change', async e => {
    if (e.target.id !== 'stEbpfDebug') return;
    const on = e.target.checked;
    e.target.disabled = true;
    try {
      const msg = await apiPatch('/api/config', { ebpf_debug_enabled: on });
      toast(typeof msg === 'string' ? msg : '配置已更新');
      if (cfg) cfg.ebpf_debug_enabled = on;
    } catch (err) {
      e.target.checked = !on;
      toast(err.message, 'err');
    } finally { e.target.disabled = false; }
  });

  loadAll();

  return () => {};
}
