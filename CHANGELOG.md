# Changelog

## 0.3.1 (2026-06-20)

### 重大变更

- **移除 WAF 与 Challenge 模块**：项目重新聚焦网络层 DDoS 清洗，不再内置 HTTP WAF 与 JS Challenge 能力，以降低 eBPF verifier 压力和代码复杂度。

### 新增

- **TCP RST 回包**：丢弃 TCP 连接时可选立即回复 RST，避免客户端持续重传。
- **RST 诊断计数器**：`tcp_rst_sent` / `tcp_rst_fail` / `tcp_rst_attempt` 统计并同步到 `/api/stats`。
- **eBPF 全局统计同步**：`total_packets`、`total_dropped`、`total_passed` 以及各分类计数改由 eBPF Per-CPU `GLOBAL_STATS` 每秒同步到用户态，避免 Ring Buffer 事件丢失/重复导致的统计失真。
- **Ring Buffer 防污染**：启动时 drain 残留事件，并基于 `CLOCK_MONOTONIC` 时间戳过滤 stale 事件。
- **控制台侧边栏重组**：分为“统计 / 防护项目 / 防护策略 / 攻击日志 / 系统”五个分组。
- **控制台动态卡片**：总览页指标数字增加计数动画、涨跌箭头、实时呼吸灯和 30 点 Sparkline 趋势图。
- **认证与令牌管理**：CLI 支持 `reset-token`，控制台登录页支持防暴力破解。
- **集成测试增强**：新增 `tests/full_attack_test.sh`，覆盖 UDP/ICMP/SYN Flood 完整攻防场景。

### 改进

- 优化事件消费器 CPU 占用：批量消费 + 批间 sleep，避免饿死 Web/API。
- 调整自适应引擎触发逻辑，仅在启用时处理事件并扩大消费批量。
- 隐藏控制台侧边栏滚动条，保持可滚动但视觉更干净。
- 同步重写中文/英文 README，移除 WAF/Challenge 描述，补充攻击者成本分析。

### 修复

- 修复 Port ACL dport 字节序读取问题。
- 修复 WAF DROP 路径未回 RST 的问题（后续随 WAF 整体移除）。
- 修复 `GLOBAL_STATS` 从 PerCpuArray 用户态读取丢失 CPU 值的问题。

---

## 0.2.0

- 初始完整功能版本：eBPF/XDP 数据面、Rust 控制面、Dashboard、CLI、TUI、审计日志、GeoIP、威胁情报、自适应阈值、防护项目分组等。
