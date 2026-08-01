/* 防护策略页：全局防御模块开关/参数 + 防护项目管理。 */
import { apiGet, apiPost, apiPatch } from '../api.js';
import { $, $$, esc, fmtCn, isValidCidr } from '../format.js';
import { store } from '../store.js';
import { toast, skeleton, emptyState, errorState, openDrawer, closeDrawer } from '../ui.js';
import { icon } from '../icons.js';

export const id = 'policy';
export const title = '防护策略';
export const sub = '全局模块开关与参数 · 防护项目分组';

/* 模块 id → PATCH /api/config 顶层开关字段；在列的模块为 switch-only，改动立即 PATCH */
const MODULE_PATCH_MAP = {
  syn_flood: 'syn_proxy_enabled',
  udp_flood: 'udp_flood_enabled',
  icmp_flood: 'icmp_flood_enabled',
  l7_scan: 'l7_scan_enabled',
  geoip: 'geoip_enabled',
  tcp_reset: 'tcp_reset_on_drop',
  trust_score: 'trust_enabled',
};

/* rate_limit / port_rate_limit / adaptive：参数表单模块，"保存"时提交完整子对象（含当前 enabled） */
const FORM_MODULES = new Set(['rate_limit', 'port_rate_limit', 'adaptive']);
/* 数值字段最小合法值（decay_den 为除数，不可为 0） */
const FIELD_MIN = { threshold: 1, tick_ms: 1, decay_num: 0, decay_den: 1, window_s: 1, block_duration_s: 1 };

/* 模块 enabled 状态 ↔ /api/config 快照字段（PATCH 后同步卡片状态点） */
const CONFIG_ENABLED = {
  syn_flood: c => !!c.syn_proxy_enabled,
  udp_flood: c => !!c.udp_flood_enabled,
  icmp_flood: c => !!c.icmp_flood_enabled,
  rate_limit: c => !!c.rate_limit?.enabled,
  port_rate_limit: c => !!c.port_rate_limit?.enabled,
  adaptive: c => !!c.adaptive?.enabled,
  l7_scan: c => !!c.l7_scan_enabled,
  geoip: c => !!c.geoip_enabled,
  tcp_reset: c => !!c.tcp_reset_on_drop,
  trust_score: c => !!c.trust_enabled,
  danger_signal: c => (c.danger_level || 0) > 0,
  port_acl: c => (c.port_acl || []).length > 0,
};

/* 防护项目可绑定的模块（与后端 validate_protection_projects 白名单一致） */
const PROJECT_MODULES = [
  { id: 'syn_flood', name: 'SYN Flood 防护' },
  { id: 'udp_flood', name: 'UDP Flood 防护' },
  { id: 'icmp_flood', name: 'ICMP Flood 防护' },
  { id: 'rate_limit', name: '速率限制 / CC 防护' },
  { id: 'adaptive', name: '自适应黑名单' },
  { id: 'l7_scan', name: 'L7 指纹扫描' },
  { id: 'geoip', name: 'GeoIP 地区封禁' },
  { id: 'tcp_reset', name: 'TCP RST 回包' },
  { id: 'port_acl', name: '端口 ACL' },
];

const DANGER_TEXT = ['L0 · 平稳', 'L1 · 警戒', 'L2 · 危险'];
const PROJECT_ACTIONS = { defend: ['tag-geo', '防御'], pass: ['tag-pass', '放行'], drop: ['tag-drop', '丢弃'] };
const MAX_PROJECTS = 256;

export function mount(el) {
  el.innerHTML = `
    <div id="plRoot">
      <section class="card">
        <div class="card-head">
          <div><div class="card-title">防护模块</div><div class="card-sub">全局防御开关与参数 · 改动即时生效 · 拦截计数 5s 刷新</div></div>
        </div>
        <div class="card-body"><div class="module-grid" id="plModules"><div style="grid-column:1/-1">${skeleton(240)}</div></div></div>
      </section>
      <section class="card section-gap">
        <div class="card-head">
          <div><div class="card-title">防护项目</div><div class="card-sub">按 协议 + 端口 + 目标 IP 匹配（PASS/DROP 数据面生效，DEFEND 复用全局防御，≤ ${MAX_PROJECTS} 个）</div></div>
          <div class="card-tools"><button class="btn btn-primary btn-sm" id="plAddProj">${icon('plus', 13)} 新增项目</button></div>
        </div>
        <div class="card-body"><div class="module-grid" id="plProjects"><div style="grid-column:1/-1">${skeleton(160)}</div></div></div>
      </section>
    </div>`;

  let modules = [];
  let projects = [];
  let stats = null;
  let config = store.get('config') || window.__INITIAL_CONFIG__ || {};
  let loaded = false;
  const timers = [];

  /* ---------- 模块卡片渲染 ---------- */
  function fieldHTML(m, f) {
    if (f.type === 'switch') {
      const label = m.id === 'syn_flood' && f.id === 'enabled' ? '启用 SYN Cookie 代理' : f.label;
      return `<label class="switch-row" style="grid-column:1/-1">
        <span class="field-label">${esc(label)}</span>
        <span class="switch"><input type="checkbox" data-module="${esc(m.id)}" data-field="${esc(f.id)}" ${f.value ? 'checked' : ''}><span class="track"></span></span>
      </label>`;
    }
    if (f.type === 'number') {
      return `<div class="field">
        <span class="field-label">${esc(f.label)}</span>
        <input class="input" type="number" min="0" step="1" data-module="${esc(m.id)}" data-field="${esc(f.id)}" value="${Number(f.value) || 0}">
      </div>`;
    }
    // readonly：只读文本
    let v = f.value;
    if (m.id === 'danger_signal' && f.id === 'danger_level') v = DANGER_TEXT[Math.min(Number(v) || 0, 2)];
    return `<div class="field" style="grid-column:1/-1">
      <span class="field-label">${esc(f.label)}</span>
      <div><span class="tag tag-muted">${esc(String(v))}</span></div>
    </div>`;
  }

  function moduleCardHTML(m) {
    const fields = (m.editable_fields || []).map(f => fieldHTML(m, f)).join('');
    const note = m.id === 'syn_flood'
      ? '<div class="field-hint">基础检测始终运行，开关控制 SYN Cookie 代理增强</div>' : '';
    const stat = m.stats_key
      ? `<span class="module-stat" data-stat-key="${esc(m.stats_key)}">累计拦截 ${fmtCn(stats?.[m.stats_key] ?? 0)}</span>` : '';
    const save = FORM_MODULES.has(m.id)
      ? `<button class="btn btn-primary btn-sm" style="margin-left:auto" data-save="${esc(m.id)}">保存</button>` : '';
    return `<div class="card module-card">
      <div class="module-head">
        <span class="module-name">${esc(m.name)}</span>
        <span class="status-dot ${m.enabled ? 'on' : 'off'}" data-dot="${esc(m.id)}"></span>
        <span class="tag tag-muted module-cat">${esc(m.category || '')}</span>
      </div>
      <div class="module-desc">${esc(m.description || '')}</div>
      ${note}
      <div class="module-fields">${fields}</div>
      ${(stat || save) ? `<div class="module-foot">${stat}${save}</div>` : ''}
    </div>`;
  }

  function renderModules() {
    const box = $('#plModules');
    if (!box) return;
    if (!modules.length) {
      box.innerHTML = `<div style="grid-column:1/-1">${emptyState('暂无模块信息', '后端未返回防护模块列表')}</div>`;
      return;
    }
    box.innerHTML = modules.map(moduleCardHTML).join('');
  }

  function updateStats() {
    if (!stats) return;
    $$('#plModules [data-stat-key]').forEach(n => {
      n.textContent = `累计拦截 ${fmtCn(stats[n.dataset.statKey] ?? 0)}`;
    });
  }

  /* PATCH 后按 config 快照同步状态点与 switch-only 开关；表单模块的输入保持用户编辑态 */
  function syncModuleStates() {
    modules.forEach(m => {
      const get = CONFIG_ENABLED[m.id];
      if (!get) return;
      m.enabled = get(config);
      const dot = $(`[data-dot="${m.id}"]`);
      if (dot) dot.className = `status-dot ${m.enabled ? 'on' : 'off'}`;
      if (MODULE_PATCH_MAP[m.id]) {
        const cb = $(`#plModules input[type="checkbox"][data-module="${m.id}"]`);
        if (cb) cb.checked = m.enabled;
      }
    });
  }

  async function pollStats() {
    try {
      stats = await apiGet('/api/stats');
      updateStats();
    } catch { /* 网络抖动时保持旧数据 */ }
  }

  /* PATCH 成功后重新拉取 /api/config 与 /api/stats 刷新状态 */
  async function refreshConfigStats() {
    try {
      const [c, s] = await Promise.all([apiGet('/api/config'), apiGet('/api/stats')]);
      config = c; store.set('config', c); stats = s;
      syncModuleStates();
      updateStats();
    } catch { /* 刷新失败保持现状 */ }
  }

  /* ---------- 开关 / 参数提交 ---------- */
  async function toggleModule(moduleId, checked, input) {
    const key = MODULE_PATCH_MAP[moduleId];
    if (!key) return;
    input.disabled = true;
    try {
      await apiPatch('/api/config', { [key]: checked });
      toast(`已${checked ? '启用' : '停用'}`, 'ok');
      await refreshConfigStats();
    } catch (e) {
      input.checked = !checked;   // 回滚开关
      toast(`操作失败：${e.message}`, 'err');
    } finally {
      input.disabled = false;
    }
  }

  /* 保存失败时按最近一次 config 快照回滚表单 */
  function restoreForm(moduleId, card) {
    const src = config?.[moduleId];
    if (!src || !card) return;
    $$('input[data-field]', card).forEach(inp => {
      const v = src[inp.dataset.field];
      if (v === undefined) return;
      if (inp.type === 'checkbox') inp.checked = !!v; else inp.value = v;
    });
  }

  async function saveModuleParams(moduleId, card, btn) {
    // 以当前 config 子对象为底叠上表单值，保证提交完整子对象（含当前 enabled，绝不强制 enabled:true）
    const sub = { ...(config?.[moduleId] || {}) };
    for (const inp of $$('input[data-field]', card)) {
      const fid = inp.dataset.field;
      if (inp.type === 'checkbox') { sub[fid] = inp.checked; continue; }
      const n = Math.floor(Number(inp.value));
      const min = FIELD_MIN[fid] ?? 0;
      if (!Number.isFinite(n) || n < min) {
        const label = inp.closest('.field')?.querySelector('.field-label')?.textContent || fid;
        toast(`${label}必须为 ≥ ${min} 的整数`, 'info');
        inp.focus();
        return;
      }
      sub[fid] = n;
    }
    btn.disabled = true;
    try {
      await apiPatch('/api/config', { [moduleId]: sub });
      toast('参数已保存', 'ok');
      await refreshConfigStats();
    } catch (e) {
      toast(`保存失败：${e.message}`, 'err');
      restoreForm(moduleId, card);
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------- 防护项目 ---------- */
  function renderProjects() {
    const box = $('#plProjects');
    if (!box) return;
    if (!projects.length) {
      box.innerHTML = `<div style="grid-column:1/-1">${emptyState('暂无防护项目', '点击右上角「新增项目」创建策略分组', 'shield')}</div>`;
      return;
    }
    box.innerHTML = projects.map((p, i) => {
      const [tagCls, tagText] = PROJECT_ACTIONS[p.action] || ['tag-muted', p.action || '—'];
      const targets = (p.target_ips || []).length ? p.target_ips.join('、') : '任意 IP';
      const mods = (p.enabled_modules || []).map(mid => PROJECT_MODULES.find(x => x.id === mid)?.name || mid).join('、') || '—';
      return `<div class="card module-card">
        <div class="module-head">
          <span class="module-name">${esc(p.name)}</span>
          <span class="tag ${tagCls} module-cat">${esc(tagText)}</span>
        </div>
        <div class="module-desc">${esc(p.description || '—')}</div>
        <div class="kv-list">
          <span class="k">目标</span><span class="v">${esc(String(p.protocol || 'any').toUpperCase())} / 端口 ${esc(p.dport || 'any')}</span>
          <span class="k">IP 范围</span><span class="v">${esc(targets)}</span>
          <span class="k">绑定模块</span><span class="v">${esc(mods)}</span>
        </div>
        <div class="module-foot">
          <button class="btn btn-ghost btn-sm" data-edit-proj="${i}">${icon('edit', 13)} 编辑</button>
          <button class="btn btn-danger btn-sm" data-del-proj="${i}">${icon('trash', 13)} 删除</button>
        </div>
      </div>`;
    }).join('');
  }

  function projectFormHTML(p) {
    const protos = ['tcp', 'udp', 'icmp', 'icmpv6', 'any'];
    const actions = [['defend', '防御'], ['pass', '放行'], ['drop', '丢弃']];
    return `
      <div class="field"><span class="field-label">项目名称 *</span>
        <input class="input" id="ppName" value="${esc(p?.name || '')}" placeholder="例如 web-tier"></div>
      <div class="field section-gap"><span class="field-label">描述</span>
        <input class="input" id="ppDesc" value="${esc(p?.description || '')}" placeholder="可选"></div>
      <div class="form-row section-gap">
        <div class="field"><span class="field-label">协议</span>
          <select class="select" id="ppProtocol">${protos.map(x => `<option value="${x}" ${p?.protocol === x ? 'selected' : ''}>${x.toUpperCase()}</option>`).join('')}</select></div>
        <div class="field"><span class="field-label">目的端口 *</span>
          <input class="input" id="ppDport" value="${esc(p?.dport || '')}" placeholder="1-65535 或 any"></div>
        <div class="field"><span class="field-label">动作</span>
          <select class="select" id="ppAction">${actions.map(([v, l]) => `<option value="${v}" ${p?.action === v ? 'selected' : ''}>${l}</option>`).join('')}</select></div>
      </div>
      <div class="field section-gap"><span class="field-label">目标 IP / CIDR（每行一条，留空表示任意 IP；IPv4 CIDR 下限 /24）</span>
        <textarea class="textarea" id="ppTargets" rows="3" placeholder="10.0.0.1&#10;192.168.1.0/24">${esc((p?.target_ips || []).join('\n'))}</textarea></div>
      <div class="field section-gap"><span class="field-label">绑定防御模块</span>
        <div id="ppModules">${PROJECT_MODULES.map(m => `<label class="switch-row"><span class="field-label">${esc(m.name)}</span>
          <span class="switch"><input type="checkbox" value="${esc(m.id)}" ${p?.enabled_modules?.includes(m.id) ? 'checked' : ''}><span class="track"></span></span>
        </label>`).join('')}</div></div>`;
  }

  function openProjectDrawer(editIdx) {
    const p = editIdx >= 0 ? projects[editIdx] : null;
    const drawer = openDrawer({
      headHTML: `<div class="drawer-title">${p ? '编辑防护项目' : '新增防护项目'}</div>
        <div class="card-sub">按协议 + 端口 + 目标 IP 绑定一组防御模块</div>`,
      bodyHTML: projectFormHTML(p),
      footHTML: `<button class="btn btn-ghost" data-drawer-close>取消</button>
        <button class="btn btn-primary grow" id="ppSave">${icon('check', 14)} 保存项目</button>`,
    });
    drawer.querySelector('#ppSave').addEventListener('click', () => saveProject(editIdx));
  }

  async function saveProject(editIdx) {
    const name = $('#ppName').value.trim();
    if (!name) { toast('请输入项目名称', 'info'); return; }
    const rawPort = $('#ppDport').value.trim().toLowerCase();
    let dport = rawPort;
    if (rawPort !== 'any') {
      const n = Number(rawPort);
      if (!Number.isInteger(n) || n < 1 || n > 65535) { toast('目的端口需为 1-65535 的整数或 any', 'info'); return; }
      dport = String(n);
    }
    const targets = $('#ppTargets').value.split('\n').map(s => s.trim()).filter(Boolean);
    const bad = targets.find(t => !isValidCidr(t) && !t.includes(':'));
    if (bad) { toast(`目标 IP / CIDR 无效：${bad}`, 'info'); return; }
    const badPrefix = targets.find(t => /^\d+\.\d+\.\d+\.\d+\/\d+$/.test(t) && Number(t.split('/')[1]) < 24);
    if (badPrefix) { toast(`IPv4 CIDR 下限 /24：${badPrefix}`, 'info'); return; }
    if (editIdx < 0 && projects.length >= MAX_PROJECTS) { toast(`项目数量已达上限 ${MAX_PROJECTS}`, 'err'); return; }
    const item = {
      name,
      description: $('#ppDesc').value.trim(),
      protocol: $('#ppProtocol').value,
      dport,
      target_ips: targets,
      enabled_modules: $$('#ppModules input:checked').map(i => i.value),
      action: $('#ppAction').value,
    };
    const next = projects.slice();
    if (editIdx >= 0 && editIdx < next.length) next[editIdx] = item; else next.push(item);
    try {
      await apiPost('/api/protection-projects', { projects: next });
      projects = next;
      closeDrawer();
      toast('项目已保存', 'ok');
      renderProjects();
    } catch (e) {
      toast(`保存失败：${e.message}`, 'err');
    }
  }

  async function deleteProject(idx) {
    const p = projects[idx];
    if (!p) return;
    if (!confirm(`确定删除防护项目「${p.name}」？`)) return;
    const next = projects.slice();
    next.splice(idx, 1);   // 先从本地列表移除，再 POST 全量
    try {
      await apiPost('/api/protection-projects', { projects: next });
      projects = next;
      toast('项目已删除', 'ok');
      renderProjects();
    } catch (e) {
      toast(`删除失败：${e.message}`, 'err');
    }
  }

  /* ---------- 事件委托 ---------- */
  const root = $('#plRoot');
  root.addEventListener('change', e => {
    const inp = e.target.closest('input[data-field]');
    if (!inp || inp.type !== 'checkbox') return;
    const moduleId = inp.dataset.module;
    // switch-only 模块立即 PATCH；rate_limit / adaptive 的开关仅改表单状态，随"保存"统一提交
    if (MODULE_PATCH_MAP[moduleId]) toggleModule(moduleId, inp.checked, inp);
  });
  root.addEventListener('click', e => {
    if (e.target.closest('[data-retry]')) { loadAll(); return; }
    const save = e.target.closest('[data-save]');
    if (save) { saveModuleParams(save.dataset.save, save.closest('.module-card'), save); return; }
    const edit = e.target.closest('[data-edit-proj]');
    if (edit) { openProjectDrawer(Number(edit.dataset.editProj)); return; }
    const del = e.target.closest('[data-del-proj]');
    if (del) { deleteProject(Number(del.dataset.delProj)); return; }
    if (e.target.closest('#plAddProj')) openProjectDrawer(-1);
  });

  /* ---------- 启动 / 卸载 ---------- */
  async function loadAll() {
    try {
      const [m, c, p, s] = await Promise.all([
        apiGet('/api/protection-modules'),
        apiGet('/api/config'),
        apiGet('/api/protection-projects'),
        apiGet('/api/stats'),
      ]);
      modules = m.modules || [];
      config = c; store.set('config', c);
      projects = p.projects || [];
      stats = s;
      loaded = true;
      renderModules();
      renderProjects();
    } catch (e) {
      if (!loaded) {
        const err = `<div style="grid-column:1/-1">${errorState(`加载防护策略失败：${e.message}`)}</div>`;
        const mm = $('#plModules'), pp = $('#plProjects');
        if (mm) mm.innerHTML = err;   // 页面已卸载时静默放弃
        if (pp) pp.innerHTML = err;
      } else {
        toast(`刷新失败：${e.message}`, 'err');
      }
    }
  }

  loadAll();
  timers.push(setInterval(pollStats, 5000));

  return () => {
    timers.forEach(clearInterval);
  };
}
