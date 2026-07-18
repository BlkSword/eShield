/* ECharts 助手：主题感知的基础配置、统一色盘、图表注册表（主题切换时批量刷新）。 */
import { cssVar } from './format.js';

export const PALETTE = ['#22d3ee', '#60a5fa', '#a78bfa', '#fb7185', '#fbbf24', '#34d399', '#fb923c', '#2dd4bf', '#94a3b8'];

const registry = new Set();

/** 创建图表并注册到主题刷新表。buildOption: () => echarts option */
export function createChart(el, buildOption) {
  const chart = echarts.init(el);
  const entry = { chart, buildOption };
  registry.add(entry);
  chart.setOption(buildOption());
  return {
    chart,
    update: () => chart.setOption(buildOption(), true),
    /** 增量合并（默认 merge）：同结构 series 平滑过渡，高频数据刷新不闪烁 */
    merge: () => chart.setOption(buildOption()),
    dispose: () => { registry.delete(entry); chart.dispose(); },
    resize: () => chart.resize(),
  };
}

/** 主题切换时调用：全部图表 setOption(notMerge) 刷新，不销毁重建。 */
export function refreshAllCharts() {
  registry.forEach(e => e.chart.setOption(e.buildOption(), true));
}

export function resizeAllCharts() {
  registry.forEach(e => e.chart.resize());
}

export const axisTextColor = () => cssVar('--text-2');

export function baseTooltip() {
  return {
    trigger: 'axis',
    backgroundColor: cssVar('--bg-overlay'),
    borderColor: cssVar('--border-strong'),
    borderWidth: 1,
    padding: [8, 12],
    textStyle: { color: cssVar('--text-1'), fontSize: 12 },
    axisPointer: { lineStyle: { color: cssVar('--border-strong') } },
  };
}

export function baseGrid(over = {}) {
  // top 40：给单行滚动 legend 留位，避免与 Y 轴刻度重叠
  return { left: 46, right: 14, top: 40, bottom: 26, ...over };
}

export function categoryAxis(labels, over = {}) {
  return {
    type: 'category', boundaryGap: false, data: labels,
    axisLine: { lineStyle: { color: cssVar('--border') } },
    axisTick: { show: false },
    // hideOverlap：标签密集时自动抽稀，避免相邻标签重叠
    axisLabel: { color: axisTextColor(), fontSize: 10.5, hideOverlap: true },
    ...over,
  };
}

export function valueAxis(over = {}) {
  return {
    type: 'value',
    splitLine: { lineStyle: { color: cssVar('--border') } },
    axisLabel: {
      color: axisTextColor(), fontSize: 10.5,
      formatter: v => (v >= 10000 ? (v / 1000) + 'k' : v),
    },
    ...over,
  };
}

export function baseLegend(over = {}) {
  return {
    // type 'scroll'：legend 超宽时单行滚动，不换行挤压绘图区
    type: 'scroll',
    top: 0,
    textStyle: { color: axisTextColor(), fontSize: 11 },
    icon: 'roundRect', itemWidth: 12, itemHeight: 3, itemGap: 14,
    ...over,
  };
}
