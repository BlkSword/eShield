/* 规则中心：端口 ACL、L7 指纹、GeoIP、威胁情报 四个页签。 */
import { apiGet, apiPost } from '../api.js';
import { $, $$, esc, fmtDuration } from '../format.js';
import { toast, skeleton, emptyState, errorState, openDrawer, closeDrawer } from '../ui.js';
import { icon } from '../icons.js';

export const id = 'rules';
export const title = '规则中心';
export const sub = '端口 ACL · L7 指纹 · GeoIP · 威胁情报';

const TABS = [
  { key: 'acl', label: '端口 ACL' },
  { key: 'l7', label: 'L7 指纹' },
  { key: 'geoip', label: 'GeoIP' },
  { key: 'intel', label: '威胁情报' },
];
const ACL_MAX = 128;
const L7_MAX = 16;
const PROTOCOLS = ['any', 'tcp', 'udp', 'icmp', 'icmpv6'];

const byteLen = s => new TextEncoder().encode(s).length;

/** 端口校验：* / any / 单端口 / 起-止范围（0-65535，起 ≤ 止） */
function validDport(s) {
  const v = String(s).trim();
  if (v === '*' || v.toLowerCase() === 'any') return true;
  const one = p => /^\d{1,5}$/.test(p) && Number(p) <= 65535;
  if (v.includes('-')) {
    const parts = v.split('-');
    if (parts.length !== 2) return false;
    return one(parts[0]) && one(parts[1]) && Number(parts[0]) <= Number(parts[1]);
  }
  return one(v);
}

const actionTag = a => a === 'allow'
  ? '<span class="tag tag-pass">放行</span>'
  : '<span class="tag tag-drop">丢弃</span>';

export function mount(el) {
  el.innerHTML = `
    <div class="card rules-tabs-card">
      <div class="card-head">
        <div><div class="card-title">规则中心</div><div class="card-sub">端口/协议 ACL、应用层指纹、地域与威胁情报规则</div></div>
      </div>
      <div class="tabs" id="rulesTabs">
        ${TABS.map((t, i) => `<button data-tab="${t.key}"${i === 0 ? ' class="active"' : ''}>${t.label}</button>`).join('')}
      </div>
      <div class="tab-body" id="rulesBody">${skeleton(220)}</div>
    </div>`;

  let active = 'acl';
  let loadSeq = 0;              // 防止切页签后旧请求覆盖新内容
  let aclItems = [];
  let l7Items = [];

  const body = () => $('#rulesBody');

  /* ================= 端口 ACL ================= */
  function renderAcl() {
    const rows = aclItems.map((it, i) => `
      <tr>
        <td><span class="tag tag-muted">${esc(String(it.protocol).toUpperCase())}</span></td>
        <td class="mono">${esc(it.dport)}</td>
        <td>${actionTag(String(it.action).toLowerCase())}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="btn btn-ghost btn-sm" data-act="acl:edit" data-idx="${i}">${icon('edit', 13)} 编辑</button>
          <button class="btn btn-ghost btn-sm" data-act="acl:del" data-idx="${i}">${icon('trash', 13)} 删除</button>
        </td>
      </tr>`).join('');
    return `
      <div class="filter-bar">
        <span class="field-hint" style="flex:1">按协议 + 目的端口匹配，先匹配先生效，最多 ${ACL_MAX} 条</span>
        <button class="btn btn-primary btn-sm" data-act="acl:add">${icon('plus', 13)} 新增规则</button>
      </div>
      ${aclItems.length ? `<div class="table-wrap"><table class="data">
        <thead><tr><th>协议</th><th>目的端口</th><th>动作</th><th style="text-align:right">操作</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
        : emptyState('暂无端口 ACL 规则', '点击右上角「新增规则」创建第一条规则')}`;
  }

  async function loadAcl() {
    const my = ++loadSeq;
    body().innerHTML = skeleton(220);
    try {
      const data = await apiGet('/api/port-acl');
      if (my !== loadSeq) return;
      aclItems = data.items || [];
      body().innerHTML = renderAcl();
    } catch (e) {
      if (my !== loadSeq) return;
      body().innerHTML = errorState(e.message);
    }
  }

  async function saveAcl(next, btn, errEl) {
    if (next.length > ACL_MAX) { errEl.textContent = `最多 ${ACL_MAX} 条规则`; return; }
    btn.disabled = true;
    try {
      const msg = await apiPost('/api/port-acl', { items: next });
      toast(typeof msg === 'string' ? msg : '端口 ACL 已更新');
      closeDrawer();
      loadAcl();
    } catch (e) {
      errEl.textContent = e.message;
      btn.disabled = false;
    }
  }

  function openAclDrawer(idx) {
    const isEdit = idx !== null;
    const item = isEdit ? aclItems[idx] : { protocol: 'tcp', dport: '', action: 'drop' };
    const drawer = openDrawer({
      headHTML: `<div class="drawer-title">${isEdit ? '编辑' : '新增'}端口 ACL 规则</div>`,
      bodyHTML: `
        <div class="field">
          <div class="field-label">协议</div>
          <select class="select" id="aclProto">
            ${PROTOCOLS.map(p => `<option value="${p}"${p === String(item.protocol).toLowerCase() ? ' selected' : ''}>${p.toUpperCase()}</option>`).join('')}
          </select>
        </div>
        <div class="field section-gap">
          <div class="field-label">目的端口</div>
          <input class="input mono" id="aclDport" placeholder="如 80、1000-2000 或 *" value="${esc(item.dport)}">
          <div class="field-hint">单个端口、范围（起-止），或 * 表示全部端口</div>
        </div>
        <div class="field section-gap">
          <div class="field-label">动作</div>
          <select class="select" id="aclAction">
            <option value="drop"${item.action === 'drop' ? ' selected' : ''}>丢弃</option>
            <option value="allow"${item.action === 'allow' ? ' selected' : ''}>放行</option>
          </select>
        </div>
        <div class="field-hint section-gap" id="aclErr" style="color:var(--danger)"></div>`,
      footHTML: `<button class="btn btn-primary grow" id="aclSave">${icon('check', 14)} 保存规则</button>`,
    });
    drawer.querySelector('#aclSave').addEventListener('click', () => {
      const protocol = drawer.querySelector('#aclProto').value;
      const dport = drawer.querySelector('#aclDport').value.trim();
      const action = drawer.querySelector('#aclAction').value;
      const errEl = drawer.querySelector('#aclErr');
      if (!validDport(dport)) {
        errEl.textContent = '端口格式无效：支持单端口（0-65535）、范围（如 1000-2000）或 *';
        return;
      }
      const next = aclItems.slice();
      const entry = { protocol, dport, action };
      if (isEdit) next[idx] = entry; else next.push(entry);
      saveAcl(next, drawer.querySelector('#aclSave'), errEl);
    });
  }

  /* ================= L7 指纹 ================= */
  function renderL7() {
    const rows = l7Items.map((p, i) => `
      <tr>
        <td class="mono" style="color:var(--text-3)">${i + 1}</td>
        <td class="mono">${esc(p.pattern)}</td>
        <td class="mono">${p.mask ? esc(p.mask) : '<span style="color:var(--text-3)">—（全匹配）</span>'}</td>
        <td style="text-align:right;white-space:nowrap">
          <button class="btn btn-ghost btn-sm" data-act="l7:edit" data-idx="${i}">${icon('edit', 13)} 编辑</button>
          <button class="btn btn-ghost btn-sm" data-act="l7:del" data-idx="${i}">${icon('trash', 13)} 删除</button>
        </td>
      </tr>`).join('');
    return `
      <div class="filter-bar">
        <span class="field-hint" style="flex:1">匹配 TCP 首包前 8 字节特征，命中即丢弃，最多 ${L7_MAX} 条</span>
        <button class="btn btn-primary btn-sm" data-act="l7:add">${icon('plus', 13)} 新增指纹</button>
      </div>
      ${l7Items.length ? `<div class="table-wrap"><table class="data">
        <thead><tr><th>#</th><th>特征字节</th><th>掩码</th><th style="text-align:right">操作</th></tr></thead>
        <tbody>${rows}</tbody></table></div>`
        : emptyState('暂无 L7 指纹', '点击右上角「新增指纹」创建第一条特征')}`;
  }

  async function loadL7() {
    const my = ++loadSeq;
    body().innerHTML = skeleton(220);
    try {
      const data = await apiGet('/api/l7-patterns');
      if (my !== loadSeq) return;
      l7Items = data.patterns || [];
      body().innerHTML = renderL7();
    } catch (e) {
      if (my !== loadSeq) return;
      body().innerHTML = errorState(e.message);
    }
  }

  async function saveL7(next, btn, errEl) {
    if (next.length > L7_MAX) { errEl.textContent = `最多 ${L7_MAX} 条指纹`; return; }
    btn.disabled = true;
    try {
      const msg = await apiPost('/api/l7-patterns', { patterns: next });
      toast(typeof msg === 'string' ? msg : 'L7 指纹已更新');
      closeDrawer();
      loadL7();
    } catch (e) {
      errEl.textContent = e.message;
      btn.disabled = false;
    }
  }

  function openL7Drawer(idx) {
    const isEdit = idx !== null;
    const item = isEdit ? l7Items[idx] : { pattern: '', mask: '' };
    const drawer = openDrawer({
      headHTML: `<div class="drawer-title">${isEdit ? '编辑' : '新增'}L7 指纹</div>`,
      bodyHTML: `
        <div class="field">
          <div class="field-label">特征字节（pattern）</div>
          <input class="input mono" id="l7Pattern" placeholder="如 GET / 或原始字节串" value="${esc(item.pattern)}">
          <div class="field-hint">按原始字节匹配，最长 8 字节</div>
        </div>
        <div class="field section-gap">
          <div class="field-label">掩码（mask，可选）</div>
          <input class="input mono" id="l7Mask" placeholder="留空表示全字节精确匹配" value="${esc(item.mask || '')}">
          <div class="field-hint">逐字节掩码，字节长度必须与特征一致</div>
        </div>
        <div class="field-hint section-gap" id="l7Err" style="color:var(--danger)"></div>`,
      footHTML: `<button class="btn btn-primary grow" id="l7Save">${icon('check', 14)} 保存指纹</button>`,
    });
    drawer.querySelector('#l7Save').addEventListener('click', () => {
      const pattern = drawer.querySelector('#l7Pattern').value;
      const mask = drawer.querySelector('#l7Mask').value;
      const errEl = drawer.querySelector('#l7Err');
      if (!pattern) { errEl.textContent = '特征字节不能为空'; return; }
      if (byteLen(pattern) > 8) { errEl.textContent = '特征字节最长 8 字节'; return; }
      if (mask && byteLen(mask) !== byteLen(pattern)) {
        errEl.textContent = `掩码字节长度（${byteLen(mask)}）必须与特征（${byteLen(pattern)}）一致`;
        return;
      }
      const next = l7Items.slice();
      const entry = mask ? { pattern, mask } : { pattern };
      if (isEdit) next[idx] = entry; else next.push(entry);
      saveL7(next, drawer.querySelector('#l7Save'), errEl);
    });
  }

  /* ================= GeoIP（只读 + 操作） ================= */
  function renderGeoip(cfg) {
    const g = cfg.geoip || {};
    const badges = arr => (arr && arr.length)
      ? arr.map(x => `<span class="region-badge">${esc(x)}</span>`).join(' ')
      : '<span style="color:var(--text-3)">未配置</span>';
    return `
      <div class="geoip-grid" style="padding:14px 18px 18px">
        <div>
          <div class="drawer-section-title" style="display:flex;align-items:center;gap:8px">
            配置摘要 ${g.enabled ? '<span class="tag tag-pass">已启用</span>' : '<span class="tag tag-muted">未启用</span>'}
          </div>
          <div class="kv-list">
            <span class="k">默认动作</span><span class="v">${esc(g.default_action || 'pass')}</span>
            <span class="k">国家 CSV</span><span class="v">${esc(g.country_blocks_csv || '未配置')}</span>
            <span class="k">ASN CSV</span><span class="v">${esc(g.asn_blocks_csv || '未配置')}</span>
            <span class="k">封禁国家/地区</span><span class="v">${badges(g.block_countries)}</span>
            <span class="k">放行国家/地区</span><span class="v">${badges(g.allow_countries)}</span>
            <span class="k">封禁 ASN</span><span class="v">${badges(g.block_asns)}</span>
            <span class="k">放行 ASN</span><span class="v">${badges(g.allow_asns)}</span>
          </div>
        </div>
        <div>
          <div class="drawer-section-title">操作</div>
          <p class="field-hint" style="margin:0 0 12px;line-height:1.6">
            从 CSV 文件重新加载 GeoIP 数据并应用到数据面，无需重启进程。修改规则请编辑 config.toml 的 [geoip] 段后执行配置重载。
          </p>
          <button class="btn btn-ghost" data-act="geoip:reload">${icon('refresh', 14)} 重新加载 GeoIP</button>
        </div>
      </div>`;
  }

  async function loadGeoip() {
    const my = ++loadSeq;
    body().innerHTML = skeleton(220);
    try {
      const cfg = await apiGet('/api/config');
      if (my !== loadSeq) return;
      body().innerHTML = renderGeoip(cfg);
    } catch (e) {
      if (my !== loadSeq) return;
      body().innerHTML = errorState(e.message);
    }
  }

  /* ================= 威胁情报（只读 + 操作） ================= */
  function renderIntel(cfg) {
    const feeds = cfg.threat_intel_feeds || [];
    const list = feeds.map(f => `
      <div class="feed-item">
        <div class="f-url">${esc(f.url)}</div>
        <div class="f-meta">
          ${esc(f.name)} · 动作 ${esc(f.action || 'drop')} · 置信度 ${f.confidence ?? 80} · 每 ${fmtDuration(f.interval_s || 3600)} 同步${f.category ? ` · 分类 ${esc(f.category)}` : ''}
        </div>
      </div>`).join('');
    return `
      <div style="padding:14px 18px 18px">
        <div class="form-row" style="margin-bottom:12px;align-items:center">
          <span class="field-hint" style="flex:1">定时从 Feed 拉取恶意 IP 加入黑名单，配置位于 config.toml 的 [threat_intel] 段</span>
          <button class="btn btn-ghost btn-sm" data-act="intel:sync"${feeds.length ? '' : ' disabled'}>${icon('refresh', 13)} 立即同步</button>
        </div>
        ${feeds.length ? list : emptyState('未配置威胁情报 Feed', '在 config.toml 的 [threat_intel] 段中添加 feeds 后重载配置')}
      </div>`;
  }

  async function loadIntel() {
    const my = ++loadSeq;
    body().innerHTML = skeleton(220);
    try {
      const cfg = await apiGet('/api/config');
      if (my !== loadSeq) return;
      body().innerHTML = renderIntel(cfg);
    } catch (e) {
      if (my !== loadSeq) return;
      body().innerHTML = errorState(e.message);
    }
  }

  /* ================= 页签与事件委托 ================= */
  function loadTab(key) {
    if (key === 'acl') loadAcl();
    else if (key === 'l7') loadL7();
    else if (key === 'geoip') loadGeoip();
    else loadIntel();
  }

  $('#rulesTabs').addEventListener('click', e => {
    const b = e.target.closest('[data-tab]');
    if (!b || b.dataset.tab === active) return;
    active = b.dataset.tab;
    $$('#rulesTabs button').forEach(x => x.classList.toggle('active', x === b));
    loadTab(active);
  });

  body().addEventListener('click', async e => {
    if (e.target.closest('[data-retry]')) { loadTab(active); return; }
    const btn = e.target.closest('[data-act]');
    if (!btn || btn.disabled) return;
    const [tab, act] = btn.dataset.act.split(':');
    const idx = btn.dataset.idx !== undefined ? Number(btn.dataset.idx) : null;

    if (tab === 'acl') {
      if (act === 'add') openAclDrawer(null);
      else if (act === 'edit') openAclDrawer(idx);
      else if (act === 'del') {
        btn.disabled = true;
        try {
          const msg = await apiPost('/api/port-acl', { items: aclItems.filter((_, i) => i !== idx) });
          toast(typeof msg === 'string' ? msg : '规则已删除');
          loadAcl();
        } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
      }
    } else if (tab === 'l7') {
      if (act === 'add') openL7Drawer(null);
      else if (act === 'edit') openL7Drawer(idx);
      else if (act === 'del') {
        btn.disabled = true;
        try {
          const msg = await apiPost('/api/l7-patterns', { patterns: l7Items.filter((_, i) => i !== idx) });
          toast(typeof msg === 'string' ? msg : '指纹已删除');
          loadL7();
        } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
      }
    } else if (tab === 'geoip' && act === 'reload') {
      btn.disabled = true;
      try {
        const msg = await apiPost('/api/geoip/reload');
        toast(typeof msg === 'string' ? msg : 'GeoIP 已重新加载');
        loadGeoip();
      } catch (err) { toast(err.message, 'err'); btn.disabled = false; }
    } else if (tab === 'intel' && act === 'sync') {
      btn.disabled = true;
      try {
        const msg = await apiPost('/api/threat-intel/sync');
        toast(typeof msg === 'string' ? msg : '威胁情报同步已触发');
      } catch (err) { toast(err.message, 'err'); }
      finally { btn.disabled = false; }
    }
  });

  loadTab(active);

  return () => { closeDrawer(); };
}
