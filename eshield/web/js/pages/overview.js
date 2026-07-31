/* 总览页：KPI、威胁雷达、流量趋势、实时事件流、协议分布、TOP 端口、TOP 攻击源。 */
import { apiGet } from '../api.js';
import { $, $$, esc, fmtInt, fmtCn, fmtTime, tsToDate, cssVar, protocolName, ruleInfo } from '../format.js';
import { store } from '../store.js';
import { toast, skeleton, emptyState, errorState, sparkline, countUp } from '../ui.js';
import { icon } from '../icons.js';
import { createChart, baseTooltip, baseGrid, baseLegend, categoryAxis, valueAxis, PALETTE } from '../charts.js';
import { openIpDrawer } from '../ipdrawer.js';
import { navigate } from '../router.js';

export const id = 'overview';
export const title = '总览';
export const sub = () => {
  const c = window.__INITIAL_CONFIG__ || {};
  return `${c.interface || '—'} · XDP 防护中 · 版本 v${c.version || '?'}`;
};

const KPIS = [
  { key: 'pps', label: '实时速率', icon: 'activity', tone: '--accent', unit: 'pps',
    get: s => s.current_pps, sub: s => `丢弃 ${fmtInt(s.current_dps)} pps`, spark: 'pps' },
  { key: 'dropped', label: '总拦截', icon: 'ban', tone: '--danger', cn: true,
    get: s => s.total_dropped, sub: s => `占总流量 ${s.total_packets ? (s.total_dropped / s.total_packets * 100).toFixed(2) : '0.00'}%`, spark: 'dps' },
  { key: 'blacklist', label: '黑名单拦截', icon: 'shieldCheck', tone: '--violet', cn: true,
    get: s => s.blacklist_blocked, sub: () => '动态封禁命中', spark: 'blacklist_blocked', module: null },
  { key: 'rate', label: '速率限制', icon: 'gauge', tone: '--warning', cn: true,
    get: s => s.rate_limited, sub: (s, c) => c.rate_limit?.enabled ? `阈值 ${fmtInt(c.rate_limit.threshold)} 包/窗口` : '未启用', spark: 'rate_limited', module: (s, c) => c.rate_limit?.enabled },
  { key: 'syn', label: 'SYN Flood 拦截', icon: 'waves', tone: '--info', cn: true,
    get: s => s.syn_flood_blocked, sub: (s, c) => c.syn_proxy_enabled ? 'Cookie 代理运行中' : '基础检测运行中', spark: 'syn_flood_blocked', module: (s, c) => c.syn_proxy_enabled },
  { key: 'l7', label: 'L7 / 其他防御', icon: 'layers', tone: '--success', cn: true,
    get: s => s.l7_blocked + s.geoip_blocked + s.adaptive_blocked, sub: () => 'L7 指纹 · GeoIP · 自适应', spark: 'other' },
];

const TREND_FIELDS = [
  { key: 'blacklist_blocked', name: '黑名单' },
  { key: 'syn_flood_blocked', name: 'SYN Flood' },
  { key: 'rate_limited', name: '速率限制' },
  { key: 'udp_flood_blocked', name: 'UDP Flood' },
  { key: 'icmp_flood_blocked', name: 'ICMP Flood' },
  { key: 'l7_blocked', name: 'L7 指纹' },
  { key: 'geoip_blocked', name: 'GeoIP' },
  { key: 'adaptive_blocked', name: '自适应' },
];
const RANGES = { '15m': 900, '1h': 3600, '6h': 21600, '24h': 86400 };

/* IP 字符串 → 稳定散列（用于雷达方位角） */
function hashAngle(ip) {
  let h = 0;
  for (let i = 0; i < ip.length; i++) h = (h * 31 + ip.charCodeAt(i)) >>> 0;
  return (h % 3600) / 10;   // 0-360
}

/* 威胁雷达 SVG：攻击源按散列方位 + 命中数归一化半径分布 */
function radarSVG(blips) {
  const cx = 130, cy = 130, R = 104;
  const rings = [26, 52, 78, 104];
  const ringStr = rings.map(r => `<circle class="ring${r > 80 ? ' faint' : ''}" cx="${cx}" cy="${cy}" r="${r}"/>`).join('');
  const axisStr = [0, 45, 90, 135].map(deg => {
    const a = (deg - 90) * Math.PI / 180;
    return `<line class="axis" x1="${cx}" y1="${cy}" x2="${cx + Math.cos(a) * R}" y2="${cy + Math.sin(a) * R}"/>`;
  }).join('');
  const blipStr = blips.map(b => {
    const a = (b.ang - 90) * Math.PI / 180;
    const x = cx + Math.cos(a) * b.d * R, y = cy + Math.sin(a) * b.d * R;
    const color = b.hot ? cssVar('--danger') : cssVar('--accent');
    return `<circle class="radar-blip" cx="${x}" cy="${y}" r="${b.hot ? 3.5 : 2.6}" fill="${color}" style="animation-delay:${(b.d * 0.3).toFixed(2)}s"/>`;
  }).join('');
  return `<svg class="radar-svg" viewBox="0 0 260 260">
    <defs>
      <linearGradient id="radarGrad" x1="0" y1="0" x2="1" y2="1">
        <stop offset="0" stop-color="${cssVar('--accent')}" stop-opacity=".30"/>
        <stop offset=".6" stop-color="${cssVar('--accent')}" stop-opacity=".06"/>
        <stop offset="1" stop-color="${cssVar('--accent')}" stop-opacity="0"/>
      </linearGradient>
    </defs>
    ${ringStr}${axisStr}
    <path class="radar-sweep" d="M${cx},${cy} L${cx + R},${cy} A${R},${R} 0 0 1 ${cx - R},${cy} Z"/>
    ${blipStr}
    <circle class="radar-center" cx="${cx}" cy="${cy}" r="3"/>
  </svg>`;
}

export function mount(el) {
  el.innerHTML = `
    <section class="kpi-grid" id="ovKpi">${KPIS.map(() => `<div class="card kpi-card">${skeleton(96)}</div>`).join('')}</section>
    <section class="row-main">
      <div class="card">
        <div class="card-head">
          <div><div class="card-title"><span class="tick"></span>流量与拦截趋势</div><div class="card-sub">PPS / DPS · 按防御模块分解</div></div>
          <div class="card-tools">
            <div class="seg" id="ovMode">
              <button data-mode="line" class="active">折线</button><button data-mode="stack">堆叠</button>
            </div>
            <div class="seg" id="ovRange">
              ${Object.keys(RANGES).map(r => `<button data-range="${r}" ${r === '1h' ? 'class="active"' : ''}>${r === '15m' ? '15分钟' : r === '1h' ? '1小时' : r === '6h' ? '6小时' : '24小时'}</button>`).join('')}
            </div>
          </div>
        </div>
        <div class="trend-body" id="ovTrend"></div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><div class="card-title"><span class="tick"></span>威胁态势雷达</div><div class="card-sub">TOP 攻击源方位分布</div></div>
          <div class="card-tools"><span class="tag tag-drop" id="radarCountTag">0 源</span></div>
        </div>
        <div class="radar-wrap" id="ovRadar">${skeleton(220)}</div>
        <div class="radar-legend"><span><i style="background:${cssVar('--accent')}"></i>活跃攻击源</span><span><i style="background:${cssVar('--danger')}"></i>高危 TOP3</span></div>
      </div>
    </section>
    <section class="row-trio">
      <div class="card">
        <div class="card-head"><div><div class="card-title"><span class="tick"></span>协议分布</div><div class="card-sub">丢包按协议分解</div></div></div>
        <div class="donut-body" id="ovDonut"></div>
      </div>
      <div class="card">
        <div class="card-head"><div><div class="card-title"><span class="tick"></span>TOP 被攻击端口</div><div class="card-sub">按丢包数排序</div></div></div>
        <div class="bars-body" id="ovPorts"></div>
      </div>
      <div class="card">
        <div class="card-head">
          <div><div class="card-title"><span class="tick"></span>TOP 攻击源</div><div class="card-sub">点击查看 IP 情报</div></div>
          <div class="card-tools"><button class="btn btn-ghost btn-sm" id="ovAllAttacks">查看全部</button></div>
        </div>
        <div class="attacker-list" id="ovAttackers">${skeleton(200)}</div>
      </div>
    </section>
    <section class="card feed-card">
      <div class="card-head">
        <div><div class="card-title"><span class="tick"></span>实时拦截事件</div><div class="card-sub">DROP 事件流 · 3s 刷新</div></div>
        <div class="card-tools"><span class="live-chip" style="padding:0"><span class="live-dot on"></span>live</span></div>
      </div>
      <div class="feed-list" id="ovFeed">${skeleton(200)}</div>
    </section>`;

  /* ---------- 状态 ---------- */
  let stats = null;                 // 最新 /api/stats
  let prevStats = null;
  let config = store.get('config') || window.__INITIAL_CONFIG__ || {};
  let mode = 'line', range = store.get('trendRange', '1h');   // trendRange 与攻击事件页 TOP5 趋势联动
  let seriesData = [];              // metrics/series 原始点
  let spark = { pps: [], dps: [], blacklist_blocked: [], rate_limited: [], syn_flood_blocked: [], other: [] };
  let feedLastTs = 0;
  let kpiFirstRender = true;
  let radarBlips = [];
  const timers = [];
  const charts = [];

  /* ---------- KPI ---------- */
  // 卡片 DOM 只构建一次；后续轮询仅更新文本与 sparkline，
  // 避免 innerHTML 重建导致入场动画重播（表现为每 2s 闪烁）。
  function buildKpis() {
    $('#ovKpi').innerHTML = KPIS.map((k, i) => {
      const c = cssVar(k.tone);
      return `<div class="card kpi-card" data-kpi="${k.key}" style="--kpi-tone:${c};animation-delay:${i * .05}s">
        <div class="kpi-top">
          <span class="kpi-icon">${icon(k.icon)}</span>
          <span class="kpi-label">${k.label}</span>
          ${k.module ? '<span class="status-dot off" data-kpi-dot></span>' : ''}
        </div>
        <div class="kpi-value"><span class="num" data-kpi-value>0</span>${k.unit ? `<span class="kpi-unit">${k.unit}</span>` : ''}</div>
        <div class="kpi-sub" data-kpi-sub>—</div>
        <div class="kpi-spark" data-kpi-spark></div>
      </div>`;
    }).join('');
  }

  function renderKpis() {
    if (!stats) return;
    const first = kpiFirstRender;
    if (first) buildKpis();
    KPIS.forEach(k => {
      const card = $(`#ovKpi [data-kpi="${k.key}"]`);
      if (!card) return;
      const val = k.get(stats);
      const valEl = card.querySelector('[data-kpi-value]');
      if (first) countUp(valEl, val, k.cn ? fmtCn : fmtInt);   // 数字滚动仅首次
      else valEl.textContent = k.cn ? fmtCn(val) : fmtInt(val);
      card.querySelector('[data-kpi-sub]').textContent = k.sub(stats, config);
      const dot = card.querySelector('[data-kpi-dot]');
      if (dot && k.module) dot.className = `status-dot ${k.module(stats, config) ? 'on' : 'off'}`;
      card.querySelector('[data-kpi-spark]').innerHTML = sparkline(spark[k.spark], cssVar(k.tone));
    });
    kpiFirstRender = false;
  }

  function pushSpark() {
    if (!stats || !prevStats) return;
    const dt = 2; // 轮询间隔 2s
    spark.pps.push(stats.current_pps);
    spark.dps.push(stats.current_dps);
    spark.blacklist_blocked.push(Math.max(0, stats.blacklist_blocked - prevStats.blacklist_blocked) / dt);
    spark.rate_limited.push(Math.max(0, stats.rate_limited - prevStats.rate_limited) / dt);
    spark.syn_flood_blocked.push(Math.max(0, stats.syn_flood_blocked - prevStats.syn_flood_blocked) / dt);
    const other = (s) => s.l7_blocked + s.geoip_blocked + s.adaptive_blocked;
    spark.other.push(Math.max(0, other(stats) - other(prevStats)) / dt);
    Object.values(spark).forEach(a => { while (a.length > 40) a.shift(); });
  }

  async function pollStats() {
    try {
      const s = await apiGet('/api/stats');
      prevStats = stats; stats = s;
      pushSpark();
      renderKpis();
      donut.merge(); ports.merge();   // 增量合并刷新，避免整图重绘闪烁
      renderAttackers();
      renderRadar();
    } catch (e) {
      if (!stats) $('#ovKpi').innerHTML = `<div class="card" style="grid-column:1/-1">${errorState(e.message)}</div>`;
    }
  }

  /* ---------- 趋势图 ---------- */
  function seriesDeltas() {
    // 累积计数 → 每秒速率
    const pts = [...seriesData].sort((a, b) => a.timestamp - b.timestamp);
    const out = { labels: [], fields: {} };
    TREND_FIELDS.forEach(f => { out.fields[f.key] = []; });
    // 采样间隔 <60s 时分钟级标签会重复（如 10:58 10:58），降级到秒级
    const interval = pts.length > 1 ? pts[1].timestamp - pts[0].timestamp : Infinity;
    const showSeconds = interval < 60;
    const p2 = n => String(n).padStart(2, '0');
    for (let i = 1; i < pts.length; i++) {
      const dt = pts[i].timestamp - pts[i - 1].timestamp;
      if (dt <= 0) continue;
      const d = tsToDate(pts[i].timestamp);
      out.labels.push(showSeconds
        ? `${p2(d.getHours())}:${p2(d.getMinutes())}:${p2(d.getSeconds())}`
        : `${p2(d.getHours())}:${p2(d.getMinutes())}`);
      TREND_FIELDS.forEach(f => {
        out.fields[f.key].push(Math.round(Math.max(0, pts[i][f.key] - pts[i - 1][f.key]) / dt));
      });
    }
    return out;
  }

  const trend = createChart($('#ovTrend'), () => {
    const { labels, fields } = seriesDeltas();
    const stack = mode === 'stack';
    return {
      color: PALETTE,
      animationDuration: 400,
      grid: baseGrid(),
      legend: baseLegend(),
      tooltip: baseTooltip(),
      xAxis: categoryAxis(labels),
      yAxis: valueAxis(),
      series: TREND_FIELDS.map(f => ({
        name: f.name, type: 'line', smooth: true, showSymbol: false,
        data: fields[f.key],
        stack: stack ? 'dps' : undefined,
        areaStyle: stack ? { opacity: .32 } : undefined,
        lineStyle: { width: stack ? 1 : 1.6 },
        emphasis: { focus: 'series' },
      })),
    };
  });
  charts.push(trend);

  async function loadSeries() {
    try {
      const data = await apiGet('/api/metrics/series', { duration_s: RANGES[range] });
      seriesData = data.series || [];
      trend.merge();
      // 用序列增量播种 sparkline
      const deltas = seriesDeltas();
      const seed = (arr) => arr.slice(-40);
      spark.blacklist_blocked = seed(deltas.fields.blacklist_blocked || []);
      spark.rate_limited = seed(deltas.fields.rate_limited || []);
      spark.syn_flood_blocked = seed(deltas.fields.syn_flood_blocked || []);
      spark.other = seed(deltas.fields.l7_blocked.map((v, i) =>
        v + (deltas.fields.geoip_blocked[i] || 0) + (deltas.fields.adaptive_blocked[i] || 0)));
      spark.dps = seriesData.map(p => p.dps ?? 0).slice(-40);
      spark.pps = seriesData.map(p => p.pps ?? 0).slice(-40);
      if (stats) renderKpis();
    } catch { trend.chart.clear(); }
  }

  $('#ovMode').addEventListener('click', e => {
    const b = e.target.closest('[data-mode]'); if (!b) return;
    mode = b.dataset.mode;
    $$('#ovMode button').forEach(x => x.classList.toggle('active', x === b));
    trend.update();
  });
  $('#ovRange').addEventListener('click', e => {
    const b = e.target.closest('[data-range]'); if (!b) return;
    range = b.dataset.range;
    store.set('trendRange', range);
    $$('#ovRange button').forEach(x => x.classList.toggle('active', x === b));
    loadSeries();
  });
  // 初始 range 可能来自 store（攻击事件页联动），同步按钮高亮
  $$('#ovRange button').forEach(x => x.classList.toggle('active', x.dataset.range === range));

  /* ---------- 威胁雷达 ---------- */
  let radarSig = '';
  function renderRadar() {
    const list = (stats?.top_attackers || []).slice(0, 8);
    const sig = JSON.stringify(list.map(a => a.ip));   // 仅 IP 列表变化时重建，保持扫描动画连续
    if (sig === radarSig) return;   // 攻击源未变化时保持扫描动画连续
    radarSig = sig;
    const box = $('#ovRadar');
    if (!box) return;
    if (!list.length) {
      box.innerHTML = '<div class="empty-state" style="padding:80px 20px"><div class="e-title">暂无攻击源</div><div class="e-sub">当前没有 DROP 记录</div></div>';
      $('#radarCountTag').textContent = '0 源';
      return;
    }
    const max = Math.max(...list.map(a => a.count), 1);
    radarBlips = list.map((a, i) => ({
      ang: hashAngle(a.ip) + (i * 7) % 15 - 7,
      d: 0.18 + Math.sqrt(a.count / max) * 0.68,
      hot: i < 3,
    }));
    box.innerHTML = radarSVG(radarBlips);
    const hot = radarBlips.filter(b => b.hot).length;
    $('#radarCountTag').textContent = `${list.length} 源 · ${hot} 高危`;
  }

  /* ---------- 实时事件流 ---------- */
  function feedRow(e) {
    const rule = ruleInfo(e.rule_id);
    return `<div class="feed-row">
      <span class="feed-time">${fmtTime(tsToDate(e.timestamp_ns))}</span>
      <span class="tag ${rule.cls}">${rule.tag}</span>
      <span class="feed-ip" data-ip="${esc(e.src_ip)}">${esc(e.src_ip)}</span>
      <span class="feed-proto">${protocolName(e.protocol)}${e.dst_port ? ':' + e.dst_port : ''}</span>
      <span class="feed-meta">${esc(e.rule_name || rule.name)}</span>
    </div>`;
  }
  async function pollFeed() {
    try {
      const data = await apiGet('/api/attack-events', { limit: 30 });
      const events = (data.events || []).sort((a, b) => a.timestamp_ns - b.timestamp_ns);
      const list = $('#ovFeed');
      if (!feedLastTs) {
        list.innerHTML = events.length
          ? events.slice(-16).reverse().map(feedRow).join('')
          : emptyState('暂无拦截事件', '当前没有 DROP 记录，一切正常');
      } else {
        const fresh = events.filter(e => e.timestamp_ns > feedLastTs);
        fresh.reverse().forEach(e => {
          list.querySelector('.empty-state')?.remove();
          list.insertAdjacentHTML('afterbegin', feedRow(e));
        });
        while (list.children.length > 40) list.lastElementChild.remove();
      }
      if (events.length) feedLastTs = events[events.length - 1].timestamp_ns;
    } catch { /* 保持旧数据 */ }
  }
  $('#ovFeed').addEventListener('click', e => {
    const ip = e.target.closest('[data-ip]');
    if (ip) openIpDrawer(ip.dataset.ip);
  });

  /* ---------- 协议分布 ---------- */
  const donut = createChart($('#ovDonut'), () => {
    const s = stats || {};
    const data = [
      { name: 'TCP', value: s.tcp_dropped || 0, itemStyle: { color: '#60a5fa' } },
      { name: 'UDP', value: s.udp_dropped || 0, itemStyle: { color: '#a78bfa' } },
      { name: 'ICMP', value: s.icmp_dropped || 0, itemStyle: { color: '#fbbf24' } },
      { name: '其他', value: s.other_dropped || 0, itemStyle: { color: '#64748b' } },
    ];
    const total = data.reduce((sum, x) => sum + x.value, 0);
    return {
      tooltip: { ...baseTooltip(), trigger: 'item', formatter: p => `${p.name}<br/>${fmtInt(p.value)} 包 · ${p.percent}%` },
      legend: { bottom: 0, textStyle: { color: cssVar('--text-2'), fontSize: 11 }, icon: 'circle', itemWidth: 8, itemHeight: 8 },
      title: { text: fmtCn(total), subtext: '总丢包', left: 'center', top: '40%',
        textStyle: { color: cssVar('--text-1'), fontSize: 20, fontWeight: 700 },
        subtextStyle: { color: cssVar('--text-3'), fontSize: 11 } },
      series: [{ type: 'pie', radius: ['56%', '76%'], center: ['50%', '46%'],
        label: { show: false },
        itemStyle: { borderRadius: 6, borderColor: cssVar('--bg-raised'), borderWidth: 2 },
        emphasis: { scaleSize: 6 }, data }],
    };
  });
  charts.push(donut);

  /* ---------- TOP 端口 ---------- */
  const ports = createChart($('#ovPorts'), () => {
    const items = (stats?.top_ports || []).slice(0, 8);
    return {
      grid: { left: 52, right: 56, top: 8, bottom: 8 },
      tooltip: { ...baseTooltip(), trigger: 'item', formatter: p => `端口 ${p.name}<br/>${fmtInt(p.value)} 次丢包` },
      xAxis: { type: 'value', splitLine: { show: false }, axisLabel: { show: false } },
      yAxis: { type: 'category', inverse: true, data: items.map(x => String(x.port)),
        axisLine: { show: false }, axisTick: { show: false },
        axisLabel: { color: cssVar('--text-1'), fontSize: 11.5, fontFamily: 'Consolas, monospace' } },
      series: [{ type: 'bar', data: items.map(x => x.count), barWidth: 11,
        itemStyle: { borderRadius: [0, 6, 6, 0],
          color: { type: 'linear', x: 0, y: 0, x2: 1, y2: 0,
            colorStops: [{ offset: 0, color: cssVar('--accent-strong') }, { offset: 1, color: cssVar('--accent') }] } },
        label: { show: true, position: 'right', color: cssVar('--text-2'), fontSize: 10.5,
          fontFamily: 'Consolas, monospace', formatter: p => fmtCn(p.value) } }],
    };
  });
  charts.push(ports);

  /* ---------- TOP 攻击源 ---------- */
  let attackersSig = '';
  function renderAttackers() {
    const list = (stats?.top_attackers || []).slice(0, 8);
    const sig = JSON.stringify(list);
    if (sig === attackersSig) return;   // 数据未变化时跳过重建，避免 DOM 抖动
    attackersSig = sig;
    const box = $('#ovAttackers');
    if (!list.length) { box.innerHTML = emptyState('暂无攻击源', '当前没有 DROP 记录'); return; }
    const max = Math.max(...list.map(a => a.count), 1);
    box.innerHTML = list.map((a, i) => {
      const rule = ruleInfo(a.rule_id);
      return `<div class="attacker-row" data-ip="${esc(a.ip)}">
        <span class="attacker-rank${i < 3 ? ' top' : ''}">${String(i + 1).padStart(2, '0')}</span>
        <div class="attacker-main">
          <div class="attacker-ip">${esc(a.ip)}</div>
          <div class="attacker-bar"><i class="${i < 3 ? 'hot' : ''}" style="width:${(a.count / max * 100).toFixed(1)}%"></i></div>
          <div class="attacker-rule">${rule.name}</div>
        </div>
        <div class="attacker-right"><div class="attacker-hits">${fmtCn(a.count)}</div></div>
      </div>`;
    }).join('');
  }
  $('#ovAttackers').addEventListener('click', e => {
    const row = e.target.closest('[data-ip]');
    if (row) openIpDrawer(row.dataset.ip);
  });
  $('#ovAllAttacks').addEventListener('click', () => navigate('attacks'));
  $('#ovKpi').addEventListener('click', e => {
    if (e.target.closest('[data-kpi]')) navigate('attacks');
  });

  /* ---------- 启动 / 卸载 ---------- */
  apiGet('/api/config').then(c => { config = c; store.set('config', c); if (stats) renderKpis(); }).catch(() => {});
  pollStats();
  loadSeries();
  pollFeed();
  timers.push(setInterval(pollStats, 2000));
  timers.push(setInterval(loadSeries, 10000));
  timers.push(setInterval(pollFeed, 3000));

  return () => {
    timers.forEach(clearInterval);
    charts.forEach(c => c.dispose());
  };
}
