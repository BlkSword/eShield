# eShield 模块耦合性评估（2026-10）

> 评估对象：v0.4.6 之后的控制台重构版本（`console/` + `eshield/web/app.html`）
> 方法：静态分层与 import / 调用关系统计、共享状态审查、前后端接口逐条核对
> 结论口径：只评价代码结构与依赖方向，不评价运行时性能

## 1. 分层结构

| 单元 | 职责 | 允许依赖 |
|---|---|---|
| `eshield-ebpf` | XDP 数据面：解析、黑白名单、Flood、L7、连接跟踪、SYN Cookie | `eshield-common` |
| `eshield-common` | eBPF/用户态共享结构体、常量、纯函数 | 无 |
| `eshield` | 控制面：配置、API、CLI/TUI、持久化、审计、告警、Hub 客户端 | `eshield-common` |
| `eshield-hub` | 分布式策略中心：策略合并、节点心跳、鉴权 | `eshield-common` |
| `console` | 控制台前端 | 仅 HTTP 契约 |

依赖方向为单向：`eshield-ebpf` / `eshield` / `eshield-hub` → `eshield-common`，
三个 crate 之间没有交叉依赖，`console` 不依赖 Rust 代码。**无循环依赖**，这是当前结构最大的优点。

## 2. 数据面（eshield-ebpf）耦合

规模：`main.rs` 975 行，其余模块均小于 410 行，总计约 2576 行。

编排方式：`main.rs` 是唯一的管线编排点，按「解析 → 白名单 → 端口 ACL → 黑名单 → 防护项目 → GeoIP →
conn_track → TCP → UDP → ICMP → L7 → 全局限速」固定顺序调用各模块；模块本身不互相编排。

跨模块调用统计（非 main 调用）：

| 被调方 | 调用方 | 说明 |
|---|---|---|
| `blacklist::add_to_blacklist` | `udp_flood`、`icmp_flood` | Flood 模块超阈值后写动态黑名单 |
| `blacklist::is_blacklisted` | `main` | 早停路径 |
| `rate_counter::update_rate_counter` | `rate_limit`、`udp_flood`、`icmp_flood` | 共享 `RATE_MAP` 计数 |
| `trust::*` | `main` | 信任分读写在 main 收口 |
| `port_rate::check_port_rate` | `main` | UDP/ICMP 的端口维度限速 |

好的部分：

- `RuntimeConfig` 是数据面所有开关/阈值的单一来源，`PROJECT_POLICY.flags` 位图让全局模块可按项目复用；
- 共享结构体统一放在 `eshield-common`，`repr(C)` 与 padding 显式声明；
- 无模块间循环调用，新增一个检测模块通常是「新增文件 + main 内一个 if 分支」。

需要关注的部分：

1. **`RuntimeConfig` 是扁平大结构**：新增模块要同时改 `eshield-common`、`init_config_map`、
   `ControlState::runtime`、`RuntimeConfigPatch`、Web 前端。属于 shotgun surgery，建议按模块拆成
   嵌套结构（如 `cfg.l7.*`、`cfg.conn_track.*`）或每模块独立 config map，并给 `RuntimeConfig` 加版本号。
2. **`RATE_MAP` 被 3 个模块共享**，`BLACKLIST` 被 3 个模块写：这是性能取向的合理取舍，但意味着
   `rate_limit`、`udp_flood`、`icmp_flood` 不能独立演进；应把「阈值窗口语义 + 黑名单写入」固化为
   共享契约并有对应单元测试。
3. **`main.rs` 偏厚**：`check_tcp_drop` / `check_udp_drop` / `check_icmp_drop` / `check_l7_drop` /
   `check_rate_limit_drop` 都内联在 main；建议拆到 `pipeline/` 子模块，让 main 只保留解析与调度。

评分：**8 / 10**。

## 3. 控制面（eshield）耦合

规模：`control.rs` 1867 行、22 个 `pub async fn`；`web.rs` 1787 行；`main.rs` 1156 行；`config.rs` 1154 行。
`control.rs` 同时管理 blacklist、whitelist、GeoIP、port ACL、L7、protection projects、runtime
patch、adaptive、Hub 策略合并与持久化，是典型的**上帝对象**。

`web.rs` 对 `ControlState` 内部字段的直接访问：

| 内部字段 | web.rs 访问次数 |
|---|---:|
| `control.runtime` | 6 |
| `control.ebpf` | 3 |
| `control.whitelist` | 1 |
| `control.hub_config` | 2 |
| `stats.timeseries` | 2 |
| `packet_log` | 3 |

`web.rs` 还混有路由、请求 DTO、业务 handler、Prometheus 文本渲染与静态资源表，单文件承担了
API 层、展示层与资源层三种职责。

问题：

- 领域边界弱：黑名单/白名单/GeoIP/ACL/L7/项目没有独立的策略对象或 trait，全部由 `ControlState`
  直接操作 eBPF map 与 redb；
- 封装被绕过：`ControlState` 的 `ebpf`、`whitelist` 等字段是 `pub`，Web 层直接加锁访问内部 map；
- 变更面大：改一个策略域往往同时动 `control.rs`、`web.rs`、`config.rs`、前端。

建议（按收益排序）：

1. `web.rs` 拆分为 `web/mod.rs`、`web/api/*.rs`、`web/assets.rs`、`web/dto.rs`；本轮新增的
   blacklist/whitelist GET handler 可作为首批下沉到 `web/api/access.rs`。
2. `control.rs` 按策略域拆子模块，定义 `BlacklistStore` / `GeoIpStore` / `PortAclStore` 等 trait，
   `ControlState` 退化为 facade，只负责依赖注入与审计。
3. `ControlState` 字段改私有，Web 通过 `list_blacklist()`、`list_whitelist()`、`runtime_snapshot()`
   等只读方法访问；禁止直接 `control.ebpf.lock()`。
4. 规则显示名统一到 `eshield-common::rules::display_name()`；本轮已把 `web.rs` 内
   `attack_events_handler` 的重复 match 收敛到 `rule_display_name`，下一步是上移到 `eshield-common`。

评分：**5 / 10**。

## 4. Hub 与持久化耦合

- `hub_client.rs` 486 行，通过 `eshield-common::SharedPolicy` 与 Hub 交换策略，未直接依赖 `control.rs`；
- `store.rs` 535 行，redb 表与序列化集中在内部；
- `blacklist_sync.rs` 205 行，职责单一：扫描 eBPF `BLACKLIST` → 增量写 store；
- `adaptive.rs`、`threat_intel.rs`、`geoip.rs` 各自独立，依赖 `eshield-common` 与 `control` 的公开方法。

Hub 侧的合并规则（本地优先、tombstone、`source_nodes` 过滤）目前散落在 `control.rs`
的 `apply_hub_policies` / `unblock_hub_policies` 中，建议抽成 `policy_merge.rs` 并补单元测试，
否则「本地策略与 Hub 下发的冲突」会长期是回归高发区。

评分：**7 / 10**。

## 5. 前后端契约

本轮逐条核对 `console/src/api/client.ts` 的调用与 `eshield/src/web.rs` 的路由后，发现并修复：

| 问题 | 修复 |
|---|---|
| 前端 `GET /api/blacklist`、`GET /api/whitelist` 无后端路由 | 新增两个 handler，返回 `entries`（黑名单来自 eBPF `BLACKLIST` 实时表，白名单来自 `ControlState.whitelist`） |
| `/api/metrics/series` 返回 `{series}`，前端按数组消费 | 前端归一化层统一拆 envelope |
| `/api/protection-modules` 返回 `{modules}` 且字段为 `category/stats_key/editable_fields` | 归一化为前端 `group/statsKey/fields` |
| `/api/attack-events`、`/api/packets`、`/api/audit` 均带 envelope，且字段名不同 | 统一在 `client.ts` 做字段映射（协议号、动作号、规则名、时间戳、payload_hex） |
| `/api/metrics/series` 时间戳为单调秒，前端需要 wall-clock | 后端新增 `timestamp_ns` 字段（wall-clock 纳秒），保留原字段兼容 |
| 前端传 `?hours=24`，后端参数是 `duration_s` | 前端改为 `?duration_s=86400` |
| 模块开关前端拼 `{id}_enabled`，后端 `RuntimeConfigPatch` 并不存在该字段 | 新增 `modulePatch()` 映射（含 `port_rate_limit` 整体对象、`adaptive` 对象） |
| `/api/l7-patterns` 校验 16 > map 容量 8；`/api/port-acl` 校验 128 > map 容量 32 | 两端改为 `eshield_common::MAX_L7_PATTERNS` / `MAX_PORT_ACL`，`init_l7_patterns_map` 同步改为按常量清理/写入 |
| `DELETE /api/blacklist` 对不存在 IP 返回底层错误 | `unblock_ip_key` 改为幂等 |
| IP 详情抽屉只读 mock 数据 | 接入 `/api/ip-detail` + `/api/ip-series` |
| GeoIP 重载、威胁情报同步、Hub 节点列表只弹 toast | 分别接入 `/api/geoip/reload`、`/api/threat-intel/sync`、`/api/hub/status`、`/api/hub/proxy/nodes` |

现状与验证：

- 前端所有 HTTP 调用集中在 `console/src/api/client.ts`，后端 snake_case 与前端 camelCase 的差异
  只在这一层出现；
- 新增 `console/scripts/mockapi.py`：按真实后端 envelope 提供 mock API；
- 新增 `console/scripts/wiring.mjs`：用无头 Chrome 驱动构建产物，对总览、攻击、包日志、审计、
  模块、访问控制三 Tab、L7、项目、GeoIP、Hub、设置以及 IP 详情抽屉做端到端接线断言；
  本轮 11 个页面 + 抽屉全部 `live` 通过，无 page error。

剩余风险：DTO 仍是手工同步，后端改字段前端只能靠运行时发现。建议：
(a) 把 `wiring.mjs` 纳入 CI（`node console/scripts/wiring.mjs` + mockapi）；
(b) 中期用 `ts-rs` / `schemars` 从 Rust DTO 生成 TS 类型，或为每个路由加 Rust 侧契约测试。

评分：修复后 **7 / 10**，主要缺口是缺少编译期契约。

## 6. 总体结论

| 维度 | 评分 | 说明 |
|---|---:|---|
| 分层与依赖方向 | 9 / 10 | 三 crate 单向依赖，无循环 |
| 数据面内聚 | 8 / 10 | main 编排清晰，模块可插拔；`RuntimeConfig` 扁平、`main.rs` 偏厚 |
| 控制面内聚 | 5 / 10 | `control.rs` / `web.rs` 双上帝对象，内部字段被 Web 直接访问 |
| Hub / 持久化 | 7 / 10 | 边界清楚；策略合并规则待抽离 |
| 前后端契约 | 7 / 10 | 已逐条对齐并有端到端接线测试；缺少编译期生成 |

**总评：耦合性“不差，但成熟度不均”。** 数据面与 crate 边界是明显优点；主要债务集中在控制面的
`control.rs` / `web.rs` 两个大文件和扁平的 `RuntimeConfig`。这些不是“错误”，但会持续放大
每次新增模块的改动成本。建议按以下优先级处理：

- **P0**：`web.rs` / `control.rs` 拆分；`ControlState` 字段私有化；前后端接线测试进 CI。
- **P1**：`RuntimeConfig` 按模块分组；规则显示名上移到 `eshield-common`；Hub 合并规则抽离。
  旧 `eshield/web/{index.html,css,js}` 与 `eshield/src/{echarts.min.js,login.html}` 已删除，
  musl release 二进制回落到 8.71MB。
- **P2**：eBPF `main.rs` 管线拆分；每模块独立 config map；共享 `RATE_MAP` / `BLACKLIST` 契约测试。
