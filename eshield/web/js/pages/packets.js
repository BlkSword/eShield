/* 包日志页：eBPF 采样包明细，过滤参数服务端生效，5s 自动刷新。 */
import { apiGet } from '../api.js';
import { $, esc, fmtInt, fmtTime, tsToDate, protocolName, ruleInfo } from '../format.js';
import { store } from '../store.js';
import { skeleton, emptyState, errorState } from '../ui.js';
import { icon } from '../icons.js';
import { openIpDrawer } from '../ipdrawer.js';

export const id = 'packets';
export const title = '包日志';
export const sub = '采样包明细 · 服务端过滤';

const PROTOCOLS = [
  { v: '', label: '全部协议' },
  { v: '6', label: 'TCP' },
  { v: '17', label: 'UDP' },
  { v: '1', label: 'ICMP' },
  { v: '58', label: 'ICMPv6' },
];
const ACTIONS = [
  { v: '', label: '全部动作' },
  { v: '0', label: 'DROP' },
  { v: '1', label: 'PASS' },
];

export function mount(el) {
  el.innerHTML = `
    <div class="card" id="pkCard">
      <div class="card-head">
        <div><div class="card-title">包日志</div><div class="card-sub">按条件查询最近 200 条采样 · 点击源 IP 查看情报</div></div>
        <div class="card-tools">
          <span class="status-dot on" id="pkDot"></span>
          <span class="card-sub" id="pkLive">5s 自动刷新</span>
          <span class="tag tag-muted" id="pkCount">—</span>
        </div>
      </div>
      <div class="filter-bar" id="pkFilters">
        <input class="input" id="pkIp" placeholder="源 IP" style="min-width:150px">
        <input class="input" id="pkPort" type="number" min="1" max="65535" placeholder="目的端口">
        <select class="select" id="pkProto">
          ${PROTOCOLS.map(p => `<option value="${p.v}">${p.label}</option>`).join('')}
        </select>
        <select class="select" id="pkAction">
          ${ACTIONS.map(a => `<option value="${a.v}">${a.label}</option>`).join('')}
        </select>
        <input class="input" id="pkRule" type="number" min="0" placeholder="规则 ID">
        <button class="btn btn-primary btn-sm" id="pkSearch">${icon('search', 14)} 查询</button>
        <div class="switch-row" style="margin-left:auto">
          <label class="switch"><input type="checkbox" id="pkAuto" checked><span class="track"></span></label>
          <span style="font-size:12px;color:var(--text-2)">自动刷新 · 5s</span>
        </div>
      </div>
      <div id="pkState">${skeleton(280)}</div>
      <div class="table-wrap" id="pkWrap" style="display:none">
        <table class="data">
          <thead><tr><th>时间</th><th>动作</th><th>源地址</th><th>目的端口</th><th>协议</th><th>长度</th><th>规则</th><th>载荷预览</th></tr></thead>
          <tbody id="pkBody"></tbody>
        </table>
      </div>
    </div>`;

  /* ---------- 状态 ---------- */
  let entries = [];
  let loaded = false;
  let timer = null;
  // 采样开关：先用缓存配置快速判断，mount 时再拉一次 /api/config 确认
  let samplingOn = store.get('config')?.packet_log_enabled ?? null;

  // 过滤参数透传到 API query（空值由 api 层自动省略）
  const params = () => {
    const q = { limit: 200 };
    const ip = $('#pkIp').value.trim();
    const port = parseInt($('#pkPort').value, 10);
    const proto = $('#pkProto').value;
    const action = $('#pkAction').value;
    const rule = parseInt($('#pkRule').value, 10);
    if (ip) q.ip = ip;
    if (!Number.isNaN(port)) q.port = Math.min(65535, Math.max(1, port));
    if (proto !== '') q.protocol = +proto;
    if (action !== '') q.action = +action;
    if (!Number.isNaN(rule) && rule >= 0) q.rule = rule;
    return q;
  };
  const filtersActive = () => {
    const q = params();
    return !!(q.ip || q.port !== undefined || q.protocol !== undefined || q.action !== undefined || q.rule !== undefined);
  };

  function showState(html) {
    $('#pkWrap').style.display = 'none';
    const box = $('#pkState');
    box.style.display = '';
    box.innerHTML = html;
  }
  function showTable() {
    $('#pkState').style.display = 'none';
    $('#pkWrap').style.display = '';
  }

  function row(e) {
    const rule = ruleInfo(e.rule_id);
    // action=0 沿用触发规则的样式，PASS 统一绿色
    const actionTag = e.action === 0
      ? `<span class="tag ${rule.cls}">${rule.tag}</span>`
      : '<span class="tag tag-pass">PASS</span>';
    const hex = e.payload_hex || '';
    const preview = hex ? (hex.length > 24 ? hex.slice(0, 24) + '…' : hex) : '—';
    return `<tr>
      <td class="mono">${fmtTime(tsToDate(e.timestamp_ns))}</td>
      <td>${actionTag}</td>
      <td><span class="feed-ip" data-ip="${esc(e.src_ip)}">${esc(e.src_ip)}</span>${e.src_port ? `<span class="mono" style="color:var(--text-3)">:${e.src_port}</span>` : ''}</td>
      <td class="mono">${e.dst_port || '—'}</td>
      <td>${protocolName(e.protocol)}</td>
      <td class="mono">${e.packet_len} B</td>
      <td>${e.rule_id ? esc(rule.name) : '—'}</td>
      <td><span class="mono" style="font-size:11px;color:var(--text-2)" title="${esc(hex)}">${esc(preview)}</span></td>
    </tr>`;
  }

  function renderTable() {
    if (!loaded) return;
    $('#pkCount').textContent = `共 ${fmtInt(entries.length)} 条`;
    if (!entries.length) {
      if (samplingOn === false) {
        showState(emptyState('未启用包采样', '在配置文件 [packet_log] 段设置 enabled = true 并重载后开始记录', 'terminal'));
      } else {
        showState(filtersActive()
          ? emptyState('无匹配的采样包', '当前过滤条件下没有记录，调整条件后重新查询')
          : emptyState('暂无采样包', '采样已启用，等待匹配流量到达'));
      }
      return;
    }
    $('#pkBody').innerHTML = entries.map(row).join('');
    showTable();
  }

  async function load() {
    try {
      const data = await apiGet('/api/packets', params());
      entries = data.entries || [];
      loaded = true;
      renderTable();
    } catch (e) {
      // 已有数据时保留旧数据，等下一轮轮询；首屏失败才显示错误态
      if (!loaded) showState(errorState(e.message));
    }
  }

  function setAuto(on) {
    $('#pkDot').className = 'status-dot ' + (on ? 'on' : 'off');
    $('#pkLive').textContent = on ? '5s 自动刷新' : '自动刷新已暂停';
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(load, 5000);
  }

  /* ---------- 事件绑定（均在卡片内部元素上，随 innerHTML 清空自动移除） ---------- */
  $('#pkSearch').addEventListener('click', load);
  // 输入框回车等同点击查询
  $('#pkFilters').addEventListener('keydown', e => { if (e.key === 'Enter') load(); });
  $('#pkAuto').addEventListener('change', e => { setAuto(e.target.checked); load(); });

  // 事件委托：IP 抽屉 + 错误重试
  $('#pkCard').addEventListener('click', e => {
    const ip = e.target.closest('[data-ip]');
    if (ip) { openIpDrawer(ip.dataset.ip); return; }
    if (e.target.closest('[data-retry]')) { showState(skeleton(280)); load(); }
  });

  /* ---------- 启动 ---------- */
  apiGet('/api/config').then(c => {
    store.set('config', c);
    samplingOn = c.packet_log_enabled === true;
    if (loaded && !entries.length) renderTable();   // 修正空态文案
  }).catch(() => { /* 配置拉取失败时按已启用处理 */ });
  load();
  setAuto(true);

  return () => {
    if (timer) clearInterval(timer);
  };
}
