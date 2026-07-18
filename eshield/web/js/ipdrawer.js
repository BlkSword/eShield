/* IP 情报抽屉：全站共享，任何页面点击 IP 均可打开。 */
import { apiGet, apiPost, apiDelete } from './api.js';
import { $, esc, fmtInt, fmtCn, fmtTime, tsToDate, protocolName, trustFromScore, ruleInfo, isValidIpv4 } from './format.js';
import { openDrawer, closeDrawer, toast, emptyState } from './ui.js';
import { icon } from './icons.js';
import { createChart, baseTooltip, categoryAxis, valueAxis } from './charts.js';
import { store } from './store.js';

let drawerChart = null;

const DURATIONS = [
  { v: 300, label: '封禁 5 分钟' },
  { v: 3600, label: '封禁 1 小时' },
  { v: 86400, label: '封禁 1 天' },
  { v: 0, label: '永久封禁' },
];

export async function openIpDrawer(ip) {
  if (!isValidIpv4(ip) && !ip.includes(':')) {
    toast('请输入有效的 IP 地址', 'info');
    return;
  }
  let detail;
  try {
    detail = await apiGet('/api/ip-detail', { ip });
  } catch (e) {
    toast(`查询 IP 情报失败：${e.message}`, 'err');
    return;
  }

  const trust = trustFromScore(detail.trust_score);
  const statusTag = detail.blacklisted
    ? '<span class="tag tag-block">已封禁</span>'
    : '<span class="tag tag-limit">观察中</span>';

  const bodyHTML = `
    <div class="stat-grid">
      <div class="stat-cell"><div class="k">黑名单累计命中</div><div class="v">${fmtCn(detail.hit_count)}</div></div>
      <div class="stat-cell"><div class="k">采样 丢/过</div><div class="v" style="font-size:14px">${fmtInt(detail.drop_count)} / ${fmtInt(detail.pass_count)}</div></div>
    </div>
    <div class="drawer-section">
      <div class="drawer-section-title">Trust Score 信誉评分</div>
      <div class="trust-meter">
        <div class="track"><div class="fill" id="ipTrustFill" style="width:0%"></div></div>
        <div class="scale"><span>0 · 恶意</span><span id="ipTrustValue">${detail.trust_score}</span><span>100 · 可信</span></div>
      </div>
    </div>
    <div class="drawer-section">
      <div class="tabs" id="ipDrawerTabs">
        <button data-tab="samples" class="active">最近采样</button>
        <button data-tab="ports">端口分布</button>
        <button data-tab="trend">攻击趋势</button>
      </div>
      <div class="tab-pane active" id="ip-tab-samples">${renderSamples(detail.recent_samples)}</div>
      <div class="tab-pane" id="ip-tab-ports">${renderPorts(detail.top_ports)}</div>
      <div class="tab-pane" id="ip-tab-trend"><div id="ipTrendChart" style="height:180px"></div></div>
    </div>`;

  const footHTML = detail.blacklisted
    ? `<button class="btn btn-danger grow" data-act="unblock">${icon('check', 14)} 立即解封</button>`
    : `<select class="select" id="ipBlockDur" style="width:150px">
         ${DURATIONS.map(d => `<option value="${d.v}" ${d.v === 3600 ? 'selected' : ''}>${d.label}</option>`).join('')}
       </select>
       <button class="btn btn-danger grow" data-act="block">${icon('ban', 14)} 立即封禁</button>`;

  const drawer = openDrawer({
    headHTML: `
      <div class="drawer-ip">${esc(detail.ip)}</div>
      <div class="drawer-badges">
        <span class="trust-badge ${trust.cls}">${trust.label} · ${detail.trust_score}</span>
        ${statusTag}
      </div>`,
    bodyHTML,
    footHTML,
    onClose: () => { if (drawerChart) { drawerChart.dispose(); drawerChart = null; } },
  });

  /* Trust 仪表动画 */
  const fill = drawer.querySelector('#ipTrustFill');
  const score = detail.trust_score;
  fill.style.background = score < 30 ? 'var(--danger)' : score < 50 ? 'var(--warning)' : score < 80 ? 'var(--info)' : 'var(--success)';
  requestAnimationFrame(() => { fill.style.width = Math.max(2, score) + '%'; });

  /* Tabs */
  drawer.querySelector('#ipDrawerTabs').addEventListener('click', e => {
    const b = e.target.closest('[data-tab]');
    if (!b) return;
    drawer.querySelectorAll('#ipDrawerTabs button').forEach(x => x.classList.toggle('active', x === b));
    drawer.querySelectorAll('.tab-pane').forEach(p => p.classList.toggle('active', p.id === 'ip-tab-' + b.dataset.tab));
    if (b.dataset.tab === 'trend') setTimeout(() => drawerChart && drawerChart.resize(), 60);
  });

  /* 趋势图（懒加载数据） */
  loadTrend(ip);

  /* 封禁 / 解封 */
  drawer.querySelector('.drawer-foot').addEventListener('click', async e => {
    const btn = e.target.closest('[data-act]');
    if (!btn) return;
    btn.disabled = true;
    try {
      if (btn.dataset.act === 'block') {
        const dur = +drawer.querySelector('#ipBlockDur').value;
        await apiPost('/api/blacklist', { ip, duration_s: dur });
        toast(`已封禁 ${ip}`);
      } else {
        await apiDelete('/api/blacklist', { ip });
        toast(`已解封 ${ip}`);
      }
      closeDrawer();
      store.emit('blacklist:changed');
    } catch (err) {
      toast(err.message, 'err');
      btn.disabled = false;
    }
  });
}

function renderSamples(samples) {
  if (!samples || !samples.length) return emptyState('暂无采样包', '该 IP 近期没有被采样的数据包');
  const rows = samples.slice(0, 20).map(s => {
    const rule = ruleInfo(s.rule_id);
    const actionTag = s.action === 0
      ? `<span class="tag ${rule.cls}">${rule.tag}</span>`
      : '<span class="tag tag-pass">PASS</span>';
    return `<div class="feed-row">
      <span class="feed-time">${fmtTime(tsToDate(s.timestamp_ns))}</span>
      ${actionTag}
      <span class="mono" style="font-size:12px">${esc(s.src_ip)}:${s.src_port} → :${s.dst_port}</span>
      <span class="feed-meta">${protocolName(s.protocol)} · ${s.packet_len}B · ${esc(rule.name)}</span>
    </div>`;
  }).join('');
  return `<div style="display:flex;flex-direction:column;gap:2px">${rows}</div>`;
}

function renderPorts(ports) {
  if (!ports || !ports.length) return emptyState('暂无端口数据');
  const max = Math.max(...ports.map(p => p.count), 1);
  return ports.map(p => `
    <div class="mini-row">
      <span class="mono" style="width:52px">${p.port}</span>
      <div class="mini-bar"><i style="width:${(p.count / max * 100).toFixed(1)}%"></i></div>
      <span class="mono" style="color:var(--text-3)">${fmtCn(p.count)}</span>
    </div>`).join('');
}

async function loadTrend(ip) {
  try {
    const data = await apiGet('/api/ip-series', { ip, duration_s: 86400 });
    const el = document.getElementById('ipTrendChart');
    if (!el) return;
    const points = (data.series || []).filter(p => p.drop_count !== null || p.pass_count !== null);
    const labels = points.map(p => {
      const d = tsToDate(p.timestamp);
      return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
    });
    if (drawerChart) drawerChart.dispose();
    drawerChart = createChart(el, () => ({
      grid: { left: 40, right: 10, top: 24, bottom: 22 },
      tooltip: baseTooltip(),
      legend: { top: 0, textStyle: { color: 'inherit', fontSize: 10 }, icon: 'roundRect', itemWidth: 10, itemHeight: 3 },
      xAxis: categoryAxis(labels, { axisLabel: { fontSize: 10, color: 'inherit' } }),
      yAxis: valueAxis({ axisLabel: { fontSize: 10, color: 'inherit' } }),
      series: [
        { name: '丢包', type: 'line', data: points.map(p => p.drop_count ?? 0), smooth: true, showSymbol: false,
          lineStyle: { color: '#fb7185', width: 1.6 },
          areaStyle: { color: { type: 'linear', x: 0, y: 0, x2: 0, y2: 1,
            colorStops: [{ offset: 0, color: 'rgba(244,63,94,.25)' }, { offset: 1, color: 'rgba(244,63,94,0)' }] } } },
        { name: '通过', type: 'line', data: points.map(p => p.pass_count ?? 0), smooth: true, showSymbol: false,
          lineStyle: { color: '#34d399', width: 1.4 } },
      ],
    }));
  } catch { /* 趋势非关键路径，静默 */ }
}
