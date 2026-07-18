/* 格式化与展示辅助：全站唯一一份，避免各处重复实现。 */

export const $ = (s, el = document) => el.querySelector(s);
export const $$ = (s, el = document) => [...el.querySelectorAll(s)];

export const cssVar = n => getComputedStyle(document.documentElement).getPropertyValue(n).trim();

export const esc = s => String(s ?? '').replace(/[&<>"']/g, c =>
  ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

export const fmtInt = n => Number(n || 0).toLocaleString('en-US');

export function fmtCn(n) {
  n = Number(n || 0);
  if (n >= 1e8) return (n / 1e8).toFixed(2) + ' 亿';
  if (n >= 1e4) return (n / 1e4).toFixed(1) + ' 万';
  return fmtInt(n);
}

const pad2 = n => String(n).padStart(2, '0');

export const fmtTime = d => `${pad2(d.getHours())}:${pad2(d.getMinutes())}:${pad2(d.getSeconds())}`;
export const fmtDateTime = d =>
  `${d.getFullYear()}-${pad2(d.getMonth() + 1)}-${pad2(d.getDate())} ${fmtTime(d)}`;

/** wall-clock 秒/毫秒/纳秒 → Date（自动识别量级） */
export function tsToDate(ts) {
  const n = Number(ts);
  if (n > 1e17) return new Date(n / 1e6);        // 纳秒
  if (n > 1e14) return new Date(n / 1e3);        // 微秒
  if (n > 1e11) return new Date(n);              // 毫秒
  return new Date(n * 1000);                     // 秒
}

export function fmtAgo(ts) {
  const sec = Math.max(0, (Date.now() - tsToDate(ts).getTime()) / 1000);
  if (sec < 60) return `${Math.floor(sec)} 秒前`;
  if (sec < 3600) return `${Math.floor(sec / 60)} 分钟前`;
  if (sec < 86400) return `${Math.floor(sec / 3600)} 小时前`;
  return `${Math.floor(sec / 86400)} 天前`;
}

export function fmtDuration(sec) {
  sec = Number(sec || 0);
  if (sec === 0) return '永久';
  if (sec < 60) return `${sec} 秒`;
  if (sec < 3600) return `${Math.round(sec / 60)} 分钟`;
  if (sec < 86400) return `${Math.round(sec / 3600)} 小时`;
  return `${Math.round(sec / 86400)} 天`;
}

const PROTO_NAMES = { 1: 'ICMP', 6: 'TCP', 17: 'UDP', 58: 'ICMPv6' };
export const protocolName = p => PROTO_NAMES[p] || `IP:${p}`;

/** Trust Score 等级（后端 level 0-3 或分数 0-100 双兼容） */
export function trustFromLevel(level) {
  return [
    { label: '未知', cls: 'trust-neu' },
    { label: '恶意', cls: 'trust-mal' },
    { label: '可疑', cls: 'trust-sus' },
    { label: '可信', cls: 'trust-good' },
  ][level] || { label: '未知', cls: 'trust-neu' };
}
export function trustFromScore(score) {
  if (score < 30) return { label: '恶意', cls: 'trust-mal' };
  if (score < 50) return { label: '可疑', cls: 'trust-sus' };
  if (score < 80) return { label: '中性', cls: 'trust-neu' };
  return { label: '可信', cls: 'trust-good' };
}

/** 规则 ID → 名称/标签样式（与后端 rules 常量一致） */
export const RULE_MAP = {
  1: { name: '黑名单', tag: 'BLOCK', cls: 'tag-block' },
  2: { name: '速率限制', tag: 'LIMIT', cls: 'tag-limit' },
  3: { name: 'SYN Flood', tag: 'DROP', cls: 'tag-drop' },
  4: { name: 'L7 指纹', tag: 'DROP', cls: 'tag-drop' },
  5: { name: '自适应', tag: 'BLOCK', cls: 'tag-block' },
  6: { name: '端口 ACL', tag: 'DROP', cls: 'tag-drop' },
  7: { name: 'UDP Flood', tag: 'DROP', cls: 'tag-drop' },
  8: { name: 'ICMP Flood', tag: 'DROP', cls: 'tag-drop' },
  9: { name: 'GeoIP', tag: 'GEO', cls: 'tag-geo' },
  10: { name: '威胁情报', tag: 'BLOCK', cls: 'tag-block' },
};
export const ruleInfo = id => RULE_MAP[id] || { name: `规则 ${id}`, tag: 'DROP', cls: 'tag-drop' };

export function isValidIpv4(s) {
  const parts = String(s).trim().split('.');
  return parts.length === 4 && parts.every(p => /^\d{1,3}$/.test(p) && +p <= 255);
}
export function isValidCidr(s) {
  const [ip, mask] = String(s).trim().split('/');
  if (!isValidIpv4(ip)) return false;
  if (mask === undefined) return true;
  const m = Number(mask);
  return Number.isInteger(m) && m >= 0 && m <= 32;
}
