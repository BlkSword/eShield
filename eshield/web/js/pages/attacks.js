/* 攻击事件页：TOP5 攻击源趋势 + 最近 200 条 DROP 事件，客户端过滤，3s 自动刷新。 */
import { apiGet } from '../api.js';
import { $, esc, fmtInt, fmtTime, tsToDate, protocolName, ruleInfo, RULE_MAP } from '../format.js';
import { store } from '../store.js';
import { skeleton, emptyState, errorState } from '../ui.js';
import { icon } from '../icons.js';
import { createChart, baseTooltip, baseGrid, baseLegend, categoryAxis, valueAxis, PALETTE } from '../charts.js';
import { openIpDrawer } from '../ipdrawer.js';

export const id = 'attacks';
export const title = '攻击事件';
export const sub = '实时 DROP 事件流 · 客户端过滤';

const PROTOCOLS = [
  { v: '', label: '全部协议' },
  { v: '6', label: 'TCP' },
  { v: '17', label: 'UDP' },
  { v: '1', label: 'ICMP' },
  { v: '58', label: 'ICMPv6' },
];

/* 与总览页趋势图一致的时间范围（store 'trendRange' 联动） */
const RANGES = { '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400 };
const RANGE_LABELS = { '15m': '15分钟', '1h': '1小时', '6h': '6小时', '24h': '24小时' };

export function mount(el) {
  el.innerHTML = `
    <div class="card" id="atkTrendCard">
      <div class="card-head">
        <div><div class="card-title">TOP 攻击源趋势</div><div class="card-sub" id="atkTrendSub">TOP5 攻击源逐间隔丢包数 · 时间范围与总览趋势联动</div></div>
        <div class="card-tools">
          <button class="btn btn-ghost btn-sm trend-toggle" id="atkTrendToggle">${icon('chevronLeft')}<span>收起</span></button>
        </div>
      </div>
      <div class="attacker-trend-body" id="atkTrendBody">
        <div id="atkTrendState">${skeleton(200)}</div>
        <div id="atkTrendChart" style="display:none;height:100%"></div>
      </div>
    </div>
    <div class="card" id="atkCard">
      <div class="card-head">
        <div><div class="card-title">攻击事件</div><div class="card-sub">最近 200 条拦截记录 · 过滤即时生效</div></div>
        <div class="card-tools">
          <span class="status-dot on" id="atkDot"></span>
          <span class="card-sub" id="atkLive">3s 自动刷新</span>
          <span class="tag tag-muted" id="atkCount">—</span>
        </div>
      </div>
      <div class="filter-bar">
        <select class="select" id="atkRule">
          <option value="">全部规则</option>
          ${Object.entries(RULE_MAP).map(([rid, r]) => `<option value="${rid}">${esc(r.name)}</option>`).join('')}
        </select>
        <select class="select" id="atkProto">
          ${PROTOCOLS.map(p => `<option value="${p.v}">${p.label}</option>`).join('')}
        </select>
        <input class="input" id="atkIp" placeholder="源 IP" style="min-width:160px">
        <div class="switch-row" style="margin-left:auto">
          <label class="switch"><input type="checkbox" id="atkAuto" checked><span class="track"></span></label>
          <span style="font-size:12px;color:var(--text-2)">自动刷新 · 3s</span>
        </div>
      </div>
      <div id="atkState">${skeleton(280)}</div>
      <div class="table-wrap" id="atkWrap" style="display:none">
        <table class="data">
          <thead><tr><th>时间</th><th>动作</th><th>源 IP</th><th>协议</th><th>目的端口</th><th>规则</th></tr></thead>
          <tbody id="atkBody"></tbody>
        </table>
      </div>
    </div>`;

  /* ---------- 状态 ---------- */
  let events = [];      // 已拉取事件，新 → 旧
  let loaded = false;   // 首次加载是否成功过
  let timer = null;

  const filters = () => ({
    rule: $('#atkRule').value,
    proto: $('#atkProto').value,
    ip: $('#atkIp').value.trim(),
  });

  function showState(html) {
    $('#atkWrap').style.display = 'none';
    const box = $('#atkState');
    box.style.display = '';
    box.innerHTML = html;
  }
  function showTable() {
    $('#atkState').style.display = 'none';
    $('#atkWrap').style.display = '';
  }

  function row(e) {
    const rule = ruleInfo(e.rule_id);
    return `<tr>
      <td class="mono">${fmtTime(tsToDate(e.timestamp_ns))}</td>
      <td><span class="tag ${rule.cls}">${rule.tag}</span></td>
      <td><span class="feed-ip" data-ip="${esc(e.src_ip)}">${esc(e.src_ip)}</span></td>
      <td>${protocolName(e.protocol)}</td>
      <td class="mono">${e.dst_port || '—'}</td>
      <td>${esc(e.rule_name || rule.name)}</td>
    </tr>`;
  }

  function renderTable() {
    if (!loaded) return;
    const f = filters();
    const filtering = f.rule !== '' || f.proto !== '' || f.ip !== '';
    const list = events.filter(e =>
      (f.rule === '' || e.rule_id === +f.rule) &&
      (f.proto === '' || e.protocol === +f.proto) &&
      (f.ip === '' || e.src_ip.includes(f.ip)));
    $('#atkCount').textContent = filtering
      ? `筛选 ${fmtInt(list.length)} / 共 ${fmtInt(events.length)} 条`
      : `共 ${fmtInt(events.length)} 条`;
    if (!list.length) {
      showState(events.length
        ? emptyState('无匹配事件', '当前过滤条件下没有记录，尝试调整条件')
        : emptyState('暂无攻击事件', '当前没有 DROP 记录，一切正常', 'shieldCheck'));
      return;
    }
    $('#atkBody').innerHTML = list.map(row).join('');
    showTable();
  }

  async function load() {
    try {
      const data = await apiGet('/api/attack-events', { limit: 200 });
      events = (data.events || []).sort((a, b) => b.timestamp_ns - a.timestamp_ns);
      loaded = true;
      renderTable();
    } catch (e) {
      // 已有数据时保留旧数据，等下一轮轮询；首屏失败才显示错误态
      if (!loaded) showState(errorState(e.message));
    }
  }

  function setAuto(on) {
    $('#atkDot').className = 'status-dot ' + (on ? 'on' : 'off');
    $('#atkLive').textContent = on ? '3s 自动刷新' : '自动刷新已暂停';
    if (timer) { clearInterval(timer); timer = null; }
    if (on) timer = setInterval(load, 3000);
  }

  /* ---------- TOP5 攻击源趋势 ---------- */
  let trendChart = null;   // createChart 句柄（有数据后懒创建）
  let trendTimer = null;
  let trendCollapsed = false;
  let trendData = { labels: [], series: [] };

  function trendShowState(html) {
    $('#atkTrendChart').style.display = 'none';
    const box = $('#atkTrendState');
    box.style.display = '';
    box.innerHTML = html;
  }

  function buildTrendOption() {
    return {
      color: PALETTE.slice(0, 5),
      animationDuration: 400,
      grid: baseGrid(),
      legend: baseLegend(),
      tooltip: baseTooltip(),
      xAxis: categoryAxis(trendData.labels),
      yAxis: valueAxis(),
      series: trendData.series.map(s => ({
        name: s.ip, type: 'line', smooth: true, showSymbol: false,
        data: s.data, lineStyle: { width: 1.6 },
        emphasis: { focus: 'series' },
      })),
    };
  }

  async function loadAttackerTrend() {
    try {
      const stats = await apiGet('/api/stats');
      const top5 = (stats.top_attackers || []).slice(0, 5);
      if (!top5.length) { trendShowState(emptyState('暂无足够数据', '当前没有攻击源统计')); return; }
      const rangeKey = store.get('trendRange', '1h');
      $('#atkTrendSub').textContent = `TOP5 攻击源逐间隔丢包数 · ${RANGE_LABELS[rangeKey] || '1小时'}（与总览趋势联动）`;
      const results = await Promise.all(top5.map(a =>
        apiGet('/api/metrics/attacker-series', { ip: a.ip, duration_s: RANGES[rangeKey] || 3600 }).catch(() => null)));
      // 累积计数 → 逐间隔增量；各序列来自同一快照环，时间戳对齐
      const deltas = new Map();  // ip -> number[]
      let labels = [];
      const p2 = n => String(n).padStart(2, '0');
      for (const r of results) {
        if (!r) continue;
        const pts = (r.series || []).sort((a, b) => a.timestamp - b.timestamp);
        const arr = [];
        for (let i = 1; i < pts.length; i++) {
          if (pts[i].timestamp <= pts[i - 1].timestamp) continue;
          arr.push(Math.max(0, pts[i].count - pts[i - 1].count));
        }
        deltas.set(r.ip, arr);
        if (arr.length > labels.length) {
          labels = pts.slice(pts.length - arr.length).map(p => {
            const d = tsToDate(p.timestamp);
            return `${p2(d.getHours())}:${p2(d.getMinutes())}`;
          });
        }
      }
      const total = [...deltas.values()].reduce((s, a) => s + a.reduce((x, y) => x + y, 0), 0);
      if (!labels.length || total === 0) {
        trendShowState(emptyState('暂无足够数据', '该时间范围内 TOP 攻击源没有新增丢包'));
        return;
      }
      trendData = {
        labels,
        series: top5.filter(a => deltas.has(a.ip)).map(a => ({ ip: a.ip, data: deltas.get(a.ip) })),
      };
      $('#atkTrendState').style.display = 'none';
      const chartBox = $('#atkTrendChart');
      chartBox.style.display = '';
      if (trendChart) trendChart.merge();   // 增量合并，避免整图重绘闪烁
      else trendChart = createChart(chartBox, buildTrendOption);
    } catch { /* 保留旧图，等下一轮轮询 */ }
  }

  $('#atkTrendToggle').addEventListener('click', () => {
    trendCollapsed = !trendCollapsed;
    const btn = $('#atkTrendToggle');
    btn.classList.toggle('collapsed', trendCollapsed);
    btn.querySelector('span').textContent = trendCollapsed ? '展开' : '收起';
    $('#atkTrendBody').style.display = trendCollapsed ? 'none' : '';
    if (trendTimer) { clearInterval(trendTimer); trendTimer = null; }
    if (!trendCollapsed) {
      trendChart?.resize();
      loadAttackerTrend();
      trendTimer = setInterval(loadAttackerTrend, 10000);
    }
  });

  /* ---------- 事件绑定（均在卡片内部元素上，随 innerHTML 清空自动移除） ---------- */
  // 过滤改动即重渲
  $('#atkRule').addEventListener('change', renderTable);
  $('#atkProto').addEventListener('change', renderTable);
  $('#atkIp').addEventListener('input', renderTable);
  $('#atkAuto').addEventListener('change', e => setAuto(e.target.checked));

  // 事件委托：IP 抽屉 + 错误重试
  $('#atkCard').addEventListener('click', e => {
    const ip = e.target.closest('[data-ip]');
    if (ip) { openIpDrawer(ip.dataset.ip); return; }
    if (e.target.closest('[data-retry]')) { showState(skeleton(280)); load(); }
  });

  /* ---------- 启动 ---------- */
  load();
  setAuto(true);
  loadAttackerTrend();
  trendTimer = setInterval(loadAttackerTrend, 10000);   // 10s 轮询，随页面卸载停止

  return () => {
    if (timer) clearInterval(timer);
    if (trendTimer) clearInterval(trendTimer);
    trendChart?.dispose();
  };
}
