/* 审计日志页：服务端过滤 + 真分页 + SSE 实时插入 + CSV 导出。 */
import { apiGet } from '../api.js';
import { $, esc, fmtInt, fmtDateTime } from '../format.js';
import { store } from '../store.js';
import { toast, skeleton, emptyState, errorState } from '../ui.js';
import { icon } from '../icons.js';
import { openIpDrawer } from '../ipdrawer.js';

export const id = 'audit';
export const title = '审计日志';
export const sub = '操作审计与实时事件流';

/* AuditAction（serde snake_case）→ 中文名与标签配色 */
const ACTIONS = {
  block_ip:      { name: '封禁 IP',   cls: 'tag-drop' },
  unblock_ip:    { name: '解封 IP',   cls: 'tag-pass' },
  allow_cidr:    { name: '放行 CIDR', cls: 'tag-pass' },
  disallow_cidr: { name: '移除 CIDR', cls: 'tag-limit' },
  reload_config: { name: '重载配置',  cls: 'tag-geo' },
  patch_config:  { name: '修改配置',  cls: 'tag-geo' },
  start:         { name: '启动',      cls: 'tag-block' },
  stop:          { name: '停止',      cls: 'tag-block' },
  login:         { name: '登录',      cls: 'tag-limit' },
  reset_token:   { name: '重置令牌',  cls: 'tag-muted' },
};
const actionInfo = a => ACTIONS[a] || { name: a, cls: 'tag-muted' };

const PAGE_SIZES = [20, 50, 100];
const EXPORT_LIMIT = 1000;

export function mount(el) {
  el.innerHTML = `
    <section class="card">
      <div class="card-head">
        <div>
          <div class="card-title">审计日志</div>
          <div class="card-sub">控制台操作与系统事件 · 所有过滤均在服务端执行</div>
        </div>
        <div class="card-tools">
          <span class="live-chip"><span class="live-dot" id="auSseDot"></span><span id="auSseLabel">连接中</span></span>
          <button class="btn btn-ghost btn-sm" id="auExport">${icon('download', 14)} 导出 CSV</button>
        </div>
      </div>
      <div class="filter-bar" id="auFilters">
        <input class="input" id="auFilter" placeholder="搜索关键字（操作者 / 动作 / 详情）" style="min-width:220px">
        <input class="input" id="auIp" placeholder="来源 IP">
        <select class="select" id="auAction">
          <option value="">全部动作</option>
          ${Object.entries(ACTIONS).map(([k, v]) => `<option value="${k}">${v.name}</option>`).join('')}
        </select>
        <span style="color:var(--text-3);font-size:12px">从</span>
        <input class="input" type="datetime-local" id="auFrom" title="起始时间">
        <span style="color:var(--text-3);font-size:12px">至</span>
        <input class="input" type="datetime-local" id="auTo" title="结束时间">
      </div>
      <div class="feed-row" id="auNotice" style="display:none;cursor:pointer;margin:0 18px 6px;border:1px dashed var(--border-strong);justify-content:center">
        <span style="color:var(--accent);display:grid;place-items:center">${icon('zap', 13)}</span>
        <span id="auNoticeText"></span>
        <span style="color:var(--accent);font-weight:600">回到第 1 页</span>
      </div>
      <div class="table-wrap">
        <table class="data">
          <thead><tr><th>时间</th><th>操作者</th><th>动作</th><th>详情</th><th>来源 IP</th></tr></thead>
          <tbody id="auBody"></tbody>
        </table>
      </div>
      <div id="auFoot">${skeleton(280)}</div>
      <div class="pager" id="auPager"></div>
    </section>`;

  /* ---------- 状态 ---------- */
  let entries = [];        // 当前页数据
  let total = 0;           // 服务端返回的过滤后总数
  let page = 0;            // 0 基页码
  let pageSize = 20;
  let loaded = false;      // 首次加载是否完成
  let pendingNew = 0;      // 未展示的新 SSE 事件数
  let reqSeq = 0;          // 请求序号，丢弃过期响应
  let debounceTimer = null;
  const unsubs = [];

  /* ---------- 过滤与查询 ---------- */
  function currentFilters() {
    return {
      filter: $('#auFilter').value.trim(),
      ip: $('#auIp').value.trim(),
      action: $('#auAction').value,
      from: $('#auFrom').value,
      to: $('#auTo').value,
    };
  }
  function hasFilters() {
    const f = currentFilters();
    return !!(f.filter || f.ip || f.action || f.from || f.to);
  }
  // 服务端对 RFC3339 字符串做字典序比较，datetime-local 需先转 ISO（本地时区 → UTC）
  function toIso(v) {
    if (!v) return undefined;
    const d = new Date(v);
    return isNaN(d) ? undefined : d.toISOString();
  }
  function buildQuery(extra = {}) {
    const f = currentFilters();
    return {
      limit: pageSize,
      offset: page * pageSize,
      filter: f.filter || undefined,
      ip: f.ip || undefined,
      action: f.action || undefined,
      from: toIso(f.from),
      to: toIso(f.to),
      ...extra,
    };
  }

  /* ---------- 渲染 ---------- */
  function rowHtml(e, animate = false) {
    const a = actionInfo(e.action);
    const detail = JSON.stringify(e.detail ?? null);
    const short = detail.length > 60 ? detail.slice(0, 60) + '…' : detail;
    const d = new Date(e.timestamp);
    return `<tr${animate ? ' style="animation:feedIn .3s var(--ease)"' : ''}>
      <td class="mono" style="white-space:nowrap;color:var(--text-2)">${esc(isNaN(d) ? String(e.timestamp ?? '') : fmtDateTime(d))}</td>
      <td>${esc(e.actor)}</td>
      <td><span class="tag ${a.cls}">${esc(a.name)}</span></td>
      <td class="mono" style="color:var(--text-3);white-space:nowrap" title="${esc(detail)}">${esc(short)}</td>
      <td>${e.source_ip
        ? `<span class="feed-ip" data-ip="${esc(e.source_ip)}">${esc(e.source_ip)}</span>`
        : '<span style="color:var(--text-3)">—</span>'}</td>
    </tr>`;
  }

  function renderTable() {
    $('#auFoot').innerHTML = entries.length
      ? ''
      : emptyState('暂无审计记录', hasFilters() ? '当前过滤条件下没有匹配的事件' : '系统还没有记录到审计事件');
    $('#auBody').innerHTML = entries.map(e => rowHtml(e)).join('');
  }

  function renderPager() {
    const pages = Math.max(1, Math.ceil(total / pageSize));
    $('#auPager').innerHTML = `
      <span style="color:var(--text-3)">每页</span>
      <select class="select" id="auPageSize" style="width:72px;min-width:0">
        ${PAGE_SIZES.map(n => `<option value="${n}"${n === pageSize ? ' selected' : ''}>${n}</option>`).join('')}
      </select>
      <span style="color:var(--text-3)">条</span>
      <span class="spacer"></span>
      <button class="btn btn-ghost btn-sm" data-page="prev"${page <= 0 ? ' disabled' : ''}>上一页</button>
      <span>第 ${page + 1} 页 / 共 ${pages} 页（共 ${fmtInt(total)} 条）</span>
      <button class="btn btn-ghost btn-sm" data-page="next"${page >= pages - 1 ? ' disabled' : ''}>下一页</button>`;
  }

  function hideNotice() {
    pendingNew = 0;
    const n = $('#auNotice');
    if (n) n.style.display = 'none';
  }

  /* ---------- 数据加载 ---------- */
  async function load() {
    const seq = ++reqSeq;
    try {
      const data = await apiGet('/api/audit', buildQuery());
      if (seq !== reqSeq) return;   // 已有更新的请求，丢弃过期响应
      entries = data.entries || [];
      total = data.total || 0;
      loaded = true;
      hideNotice();
      renderTable();
      renderPager();
    } catch (err) {
      if (seq !== reqSeq) return;
      $('#auBody').innerHTML = '';
      $('#auFoot').innerHTML = errorState(err.message || '加载失败');
      renderPager();
    }
  }

  function scheduleReload() {
    clearTimeout(debounceTimer);
    debounceTimer = setTimeout(() => { page = 0; load(); }, 400);
  }

  /* ---------- SSE：新事件实时插入 / 提示条 ---------- */
  unsubs.push(store.on('audit', entry => {
    if (!loaded) return;            // 首屏加载会带上该事件
    if (page === 0 && !hasFilters()) {
      entries.unshift(entry);
      total += 1;
      if (entries.length > pageSize) entries.length = pageSize;
      const body = $('#auBody');
      $('#auFoot').innerHTML = '';  // 清掉可能的空态
      body.insertAdjacentHTML('afterbegin', rowHtml(entry, true));
      while (body.children.length > pageSize) body.lastElementChild.remove();
      renderPager();
    } else {
      pendingNew += 1;
      $('#auNoticeText').textContent = `有 ${pendingNew} 条新事件未显示`;
      $('#auNotice').style.display = 'flex';
    }
  }));

  /* ---------- SSE 连接状态徽标 ---------- */
  function renderSse(status) {
    const dot = $('#auSseDot');
    if (!dot) return;
    dot.className = 'live-dot' + (status === 'connected' ? ' on' : status === 'error' ? ' err' : '');
    $('#auSseLabel').textContent =
      status === 'connected' ? '实时流已连接' : status === 'error' ? '实时流重连中' : '实时流连接中';
  }
  unsubs.push(store.on('sse', renderSse));
  renderSse(store.get('sse', 'connecting'));

  /* ---------- CSV 导出（按当前过滤条件，最多 1000 条） ---------- */
  function csvCell(v) {
    const s = String(v ?? '');
    return /[",\r\n]/.test(s) ? '"' + s.replace(/"/g, '""') + '"' : s;
  }
  async function exportCsv() {
    const btn = $('#auExport');
    btn.disabled = true;
    try {
      const data = await apiGet('/api/audit', buildQuery({ limit: EXPORT_LIMIT, offset: 0 }));
      const rows = (data.entries || []).map(e => [
        e.timestamp, e.actor, e.action, JSON.stringify(e.detail ?? null), e.source_ip || '',
      ]);
      const csv = '\uFEFF' + [['timestamp', 'actor', 'action', 'detail', 'source_ip'], ...rows] // BOM 便于 Excel 识别 UTF-8
        .map(r => r.map(csvCell).join(',')).join('\r\n');
      const now = new Date();
      const p = n => String(n).padStart(2, '0');
      const name = `eshield-audit-${now.getFullYear()}${p(now.getMonth() + 1)}${p(now.getDate())}-${p(now.getHours())}${p(now.getMinutes())}${p(now.getSeconds())}.csv`;
      const url = URL.createObjectURL(new Blob([csv], { type: 'text/csv;charset=utf-8' }));
      const a = document.createElement('a');
      a.href = url;
      a.download = name;
      document.body.appendChild(a);
      a.click();
      a.remove();
      URL.revokeObjectURL(url);
      toast(`已导出 ${rows.length} 条审计记录`);
    } catch (err) {
      toast(`导出失败：${err.message}`, 'err');
    } finally {
      btn.disabled = false;
    }
  }

  /* ---------- 事件绑定 ---------- */
  $('#auFilters').addEventListener('input', scheduleReload);
  $('#auFilters').addEventListener('change', scheduleReload);
  $('#auNotice').addEventListener('click', () => { hideNotice(); page = 0; load(); });
  $('#auExport').addEventListener('click', exportCsv);
  $('#auPager').addEventListener('click', e => {
    const b = e.target.closest('[data-page]');
    if (!b || b.disabled) return;
    page += b.dataset.page === 'next' ? 1 : -1;
    load();
  });
  $('#auPager').addEventListener('change', e => {
    if (e.target.id !== 'auPageSize') return;
    pageSize = +e.target.value || 20;
    page = 0;
    load();
  });
  // 事件委托：[data-retry] 重试加载、点击来源 IP 打开情报抽屉
  const onRootClick = e => {
    if (e.target.closest('[data-retry]')) {
      $('#auFoot').innerHTML = skeleton(280);
      load();
      return;
    }
    const ipEl = e.target.closest('[data-ip]');
    if (ipEl) openIpDrawer(ipEl.dataset.ip);
  };
  el.addEventListener('click', onRootClick);

  /* ---------- 启动 ---------- */
  renderPager();
  load();

  return () => {
    clearTimeout(debounceTimer);
    reqSeq++;                        // 使进行中的响应失效，避免卸载后写已销毁的 DOM
    unsubs.forEach(u => u());
    el.removeEventListener('click', onRootClick);
  };
}
