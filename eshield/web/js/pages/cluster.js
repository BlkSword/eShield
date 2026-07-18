/* 集群节点：Hub 连接状态、注册节点表、共享策略表，5s 轮询。 */
import { apiGet } from '../api.js';
import { $, esc, fmtInt, fmtCn, fmtAgo, fmtDuration, ruleInfo } from '../format.js';
import { skeleton, emptyState, errorState } from '../ui.js';

export const id = 'cluster';
export const title = '集群节点';
export const sub = '分布式 Hub 连接与共享策略';

/** Hub IpKey {family, addr[16]} → 可读 IP 字符串 */
function ipFromKey(k) {
  if (!k || !Array.isArray(k.addr)) return '—';
  if (k.family === 4) return k.addr.slice(12, 16).join('.');
  if (k.family === 6) {
    const groups = [];
    for (let i = 0; i < 16; i += 2) groups.push(((k.addr[i] << 8) | k.addr[i + 1]).toString(16));
    return groups.join(':');
  }
  return '—';
}

export function mount(el) {
  el.innerHTML = `
    <section class="cluster-cards" id="clCards">
      ${'<div class="card cluster-stat">' + skeleton(64) + '</div>'.repeat(3)}
    </section>
    <section class="card section-gap">
      <div class="card-head">
        <div><div class="card-title">集群节点</div><div class="card-sub">Hub 注册节点与在线状态 · 5s 刷新</div></div>
      </div>
      <div id="clNodes">${skeleton(140)}</div>
    </section>
    <section class="card section-gap">
      <div class="card-head">
        <div><div class="card-title">共享策略</div><div class="card-sub">Hub 聚合的集群黑名单（最多显示 200 条）</div></div>
      </div>
      <div id="clPolicies">${skeleton(140)}</div>
    </section>`;

  let status = null;        // /api/hub/status
  let hubStats = null;      // /api/hub/proxy/stats
  let statsErr = null;
  let nodesData = null;     // 节点表缓存（轮询失败时保持旧数据）
  let policiesData = null;  // 策略表缓存
  let booted = false;       // enabled 视图是否已完成首次加载
  const timer = setInterval(pollStatus, 5000);

  function statCard(label, value, sub, tone) {
    return `<div class="card cluster-stat">
      <div class="kpi-label">${label}</div>
      <div class="v"${tone ? ` style="color:var(${tone})"` : ''}>${value}</div>
      <div class="card-sub" style="margin-top:6px">${sub}</div>
    </div>`;
  }

  function renderCards() {
    const box = $('#clCards');
    if (!box) return;
    const connected = !!status?.connected;
    const url = status?.active_url || (status?.urls || [])[0] || '—';
    box.innerHTML =
      statCard('连接状态', connected ? '已连接' : '未连接',
        `节点 ${esc(status?.node_name || '—')} · ${esc(url)}`, connected ? '--success' : '--danger') +
      statCard('在线节点',
        hubStats ? `${fmtInt(hubStats.online_node_count)}<span class="kpi-unit"> / ${fmtInt(hubStats.node_count)}</span>` : '—',
        statsErr ? `统计不可用：${esc(statsErr)}` : 'Hub 注册节点总数') +
      statCard('共享策略', hubStats ? fmtCn(hubStats.policy_count) : '—', 'Hub 聚合黑名单条目');
  }

  function renderDisabled() {
    const cards = $('#clCards');
    if (cards) {
      cards.innerHTML = `<div class="card" style="grid-column:1/-1">
        ${emptyState('分布式 Hub 未启用', '在 /etc/eshield/config.toml 中配置 [hub] 段（urls / node_name / token）并重新加载后，即可加入集群共享黑名单', 'network')}
      </div>`;
    }
    const nodes = $('#clNodes'); if (nodes) nodes.innerHTML = '';
    const policies = $('#clPolicies'); if (policies) policies.innerHTML = '';
  }

  async function loadStats() {
    try {
      hubStats = await apiGet('/api/hub/proxy/stats');
      statsErr = null;
    } catch (e) {
      statsErr = e.message;
    }
    renderCards();
  }

  async function loadNodes(showSkeleton) {
    const box = $('#clNodes');
    if (!box) return;
    if (showSkeleton) box.innerHTML = skeleton(140);
    try {
      const data = await apiGet('/api/hub/proxy/nodes');
      nodesData = data.nodes || [];
      box.innerHTML = nodesData.length ? `<div class="table-wrap"><table class="data">
        <thead><tr><th>节点名称</th><th>状态</th><th>最近心跳</th></tr></thead>
        <tbody>${nodesData.map(n => `<tr>
          <td class="mono">${esc(n.name)}</td>
          <td><span class="node-status ${n.online ? 'online' : 'offline'}"><span class="dot"></span>${n.online ? '在线' : '离线'}</span></td>
          <td>${fmtAgo(n.last_seen_ns)}</td>
        </tr>`).join('')}</tbody></table></div>`
        : emptyState('暂无注册节点', 'Hub 上还没有任何节点注册');
    } catch (e) {
      if (!nodesData) box.innerHTML = errorState(e.message);
    }
  }

  async function loadPolicies(showSkeleton) {
    const box = $('#clPolicies');
    if (!box) return;
    if (showSkeleton) box.innerHTML = skeleton(140);
    try {
      const data = await apiGet('/api/hub/proxy/policies', { since: 0, limit: 200 });
      policiesData = data.policies || [];
      box.innerHTML = policiesData.length ? `<div class="table-wrap"><table class="data">
        <thead><tr><th>IP 地址</th><th>触发规则</th><th>命中次数</th><th>Trust</th><th>来源节点</th><th>TTL</th><th>最近命中</th></tr></thead>
        <tbody>${policiesData.map(p => {
          const rule = ruleInfo(p.reason);
          return `<tr>
            <td class="mono">${esc(ipFromKey(p.ip))}</td>
            <td><span class="tag ${rule.cls}">${esc(rule.name)}</span></td>
            <td class="mono">${fmtInt(p.hit_count)}</td>
            <td class="mono">${fmtInt(p.trust_score)}</td>
            <td>${esc((p.source_nodes || []).join(', ') || '—')}</td>
            <td>${fmtDuration(p.ttl_s)}</td>
            <td>${fmtAgo(p.last_seen_ns)}</td>
          </tr>`;
        }).join('')}</tbody></table></div>`
        : emptyState('暂无共享策略', '集群还没有聚合黑名单条目');
    } catch (e) {
      if (!policiesData) box.innerHTML = errorState(e.message);
    }
  }

  async function pollStatus() {
    let s;
    try {
      s = await apiGet('/api/hub/status');
    } catch (e) {
      if (!booted && !status) {
        const cards = $('#clCards');
        if (cards) cards.innerHTML = `<div class="card" style="grid-column:1/-1">${errorState(e.message)}</div>`;
      }
      return;
    }
    status = s;
    if (!s.enabled) {
      booted = false;
      hubStats = null; nodesData = null; policiesData = null;
      renderDisabled();
      return;
    }
    renderCards();
    loadStats();
    loadNodes(!booted);
    loadPolicies(!booted);
    booted = true;
  }

  /* errorState 重试：整体刷新 */
  el.addEventListener('click', e => {
    if (!e.target.closest('[data-retry]')) return;
    pollStatus();
  });

  pollStatus();

  return () => clearInterval(timer);
}
