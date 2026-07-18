/* 安全运营页：快速封禁 IP、静态黑名单展示、白名单放行管理。 */
import { apiGet, apiPost, apiDelete } from '../api.js';
import { $, esc, isValidIpv4, isValidCidr } from '../format.js';
import { store } from '../store.js';
import { toast, skeleton, errorState } from '../ui.js';
import { icon } from '../icons.js';

export const id = 'security';
export const title = '安全运营';
export const sub = '动态封禁 · 静态黑名单 · 白名单放行';

const DURATIONS = [
  { v: 300, label: '5 分钟' },
  { v: 3600, label: '1 小时' },
  { v: 86400, label: '1 天' },
  { v: 0, label: '永久' },
];

export function mount(el) {
  el.innerHTML = `
    <div class="security-grid" id="secRoot">
      <div class="card">
        <div class="card-head"><div><div class="card-title">封禁 IP</div><div class="card-sub">将恶意源 IP 加入动态黑名单</div></div></div>
        <div class="card-body">
          <div class="form-row">
            <div class="field"><span class="field-label">IP 地址（IPv4 / IPv6）</span>
              <input class="input" id="secBlockIp" placeholder="192.0.2.1 或 2001:db8::1"></div>
            <div class="field" style="flex:0 0 130px;min-width:130px"><span class="field-label">封禁时长</span>
              <select class="select" id="secBlockDur">${DURATIONS.map((d, i) => `<option value="${d.v}" ${i === 1 ? 'selected' : ''}>${d.label}</option>`).join('')}</select></div>
            <div class="field" style="flex:none;min-width:0"><button class="btn btn-danger" id="secBlockBtn">${icon('ban', 14)} 封禁</button></div>
          </div>
        </div>
        <div class="card-head section-gap"><div><div class="card-title">静态黑名单</div><div class="card-sub">配置文件内置的永久封禁条目（只读）</div></div></div>
        <div class="whitelist-tags" id="secBlacklist">${skeleton(48)}</div>
      </div>
      <div class="card">
        <div class="card-head"><div><div class="card-title">放行 CIDR</div><div class="card-sub">白名单网段跳过全部检测，直接放行</div></div></div>
        <div class="card-body">
          <div class="form-row">
            <div class="field"><span class="field-label">CIDR 网段</span>
              <input class="input" id="secAllowCidr" placeholder="10.0.0.0/8"></div>
            <div class="field" style="flex:none;min-width:0"><button class="btn btn-primary" id="secAllowBtn">${icon('check', 14)} 放行</button></div>
          </div>
        </div>
        <div class="card-head section-gap"><div><div class="card-title">白名单</div><div class="card-sub">当前生效的放行条目 · 10s 自动刷新</div></div></div>
        <div class="whitelist-tags" id="secWhitelist">${skeleton(48)}</div>
      </div>
    </div>`;

  let config = store.get('config') || null;
  const timers = [];

  function renderLists() {
    const bl = $('#secBlacklist'), wl = $('#secWhitelist');
    if (!bl || !wl) return;
    const blacklist = config?.blacklist_entries || [];
    const whitelist = config?.whitelist_entries || [];
    bl.innerHTML = blacklist.length
      ? blacklist.map(ip => `<span class="wl-tag">${esc(ip)}</span>`).join('')
      : '<span class="field-hint">暂无静态黑名单条目</span>';
    wl.innerHTML = whitelist.length
      ? whitelist.map(c => `<span class="wl-tag">${esc(c)}<button data-del-cidr="${esc(c)}" title="移除该网段">${icon('x', 12)}</button></span>`).join('')
      : '<span class="field-hint">暂无白名单条目</span>';
  }

  async function loadConfig(showErr = false) {
    try {
      config = await apiGet('/api/config');
      store.set('config', config);
      renderLists();
    } catch (e) {
      if (showErr) {
        const err = errorState(`加载配置失败：${e.message}`);
        const bl = $('#secBlacklist'), wl = $('#secWhitelist');
        if (bl) bl.innerHTML = err;
        if (wl) wl.innerHTML = err;
      }
      /* 轮询失败时保持旧数据 */
    }
  }

  async function blockIp() {
    const inp = $('#secBlockIp');
    const ip = inp.value.trim();
    if (!isValidIpv4(ip) && !ip.includes(':')) {
      toast('请输入有效的 IP 地址（IPv4 或 IPv6）', 'info');
      inp.focus();
      return;
    }
    const duration_s = Number($('#secBlockDur').value);
    const btn = $('#secBlockBtn');
    btn.disabled = true;
    try {
      await apiPost('/api/blacklist', { ip, duration_s });
      const dur = DURATIONS.find(d => d.v === duration_s)?.label || `${duration_s}s`;
      toast(`已封禁 ${ip}（${duration_s === 0 ? '永久' : dur}）`, 'ok');
      inp.value = '';
      await loadConfig();
    } catch (e) {
      toast(`封禁失败：${e.message}`, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  async function allowCidr() {
    const inp = $('#secAllowCidr');
    const cidr = inp.value.trim();
    if (!isValidCidr(cidr)) {
      toast('请输入有效的 CIDR 网段（如 10.0.0.0/8）', 'info');
      inp.focus();
      return;
    }
    const btn = $('#secAllowBtn');
    btn.disabled = true;
    try {
      await apiPost('/api/whitelist', { cidr });
      toast(`已放行 ${cidr}`, 'ok');
      inp.value = '';
      await loadConfig();
    } catch (e) {
      toast(`放行失败：${e.message}`, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  async function removeCidr(cidr, btn) {
    btn.disabled = true;
    try {
      await apiDelete('/api/whitelist', { cidr });
      toast(`已移除 ${cidr}`, 'ok');
      await loadConfig();
    } catch (e) {
      toast(`移除失败：${e.message}`, 'err');
      btn.disabled = false;
    }
  }

  /* ---------- 事件委托 ---------- */
  const root = $('#secRoot');
  root.addEventListener('click', e => {
    if (e.target.closest('[data-retry]')) { loadConfig(true); return; }
    if (e.target.closest('#secBlockBtn')) { blockIp(); return; }
    if (e.target.closest('#secAllowBtn')) { allowCidr(); return; }
    const del = e.target.closest('[data-del-cidr]');
    if (del) removeCidr(del.dataset.delCidr, del);
  });
  root.addEventListener('keydown', e => {
    if (e.key !== 'Enter') return;
    if (e.target === $('#secBlockIp')) blockIp();
    else if (e.target === $('#secAllowCidr')) allowCidr();
  });

  /* ---------- 启动 / 卸载 ---------- */
  loadConfig(true);
  timers.push(setInterval(() => loadConfig(false), 10000));

  return () => {
    timers.forEach(clearInterval);
  };
}
