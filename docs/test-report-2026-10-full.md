# eShield 0.4.7 全量功能测试报告（2026-10-11）

> 被测版本：v0.4.7（从 `main` 9437c5f 本地构建，含独立登录页修复）
> 测试形态：4 台云主机（1 防御 + 3 攻击），同 VPC 私网互通
> 测试范围：**目标功能正确性与稳健性**；本轮不测基线线速/绝对 PPS 上限
> 数据来源：`/api/stats`、`/api/config`、`/api/*`、CLI、Hub API、kmsg/dmesg、攻击侧 pktgen/hping3/scapy/wrk/iperf3

## 1. 测试环境

| 角色 | 公网 / 私网 | 规格 | 内核 / 网卡 |
|---|---|---|---|
| defense | 47.238.242.131 / 172.23.83.39 | 8 vCPU / 14 GB / 40 GB | 7.0.0-31 / virtio_net 8 队列 / MTU 8500 |
| atk1 | 47.76.136.13 / 172.23.83.40 | 8 vCPU / 14 GB / 20 GB | 7.0.0-31 / virtio_net |
| atk2 | 47.76.102.207 / 172.23.83.42 | 8 vCPU / 14 GB / 20 GB | 7.0.0-31 / virtio_net |
| atk3 | 47.76.34.233 / 172.23.83.41 | 8 vCPU / 14 GB / 20 GB | 7.0.0-31 / virtio_net |

- 防御端：eShield v0.4.7（`main` 9437c5f 本地构建），`ESHIELD_XDP_MODE=skb`（generic XDP），`web_bind=0.0.0.0:8720`，`api_token=eshield-test`。
- 管理白名单：`8.149.100.136/32`（本地出口）+ `172.23.83.41/32`（atk3，保留恢复通道）；atk1/atk2 为被测攻击源。
- 攻击工具：pktgen（内核模块，8 线程）、hping3、trafgen、scapy、wrk、iperf3、stress-ng、tcpdump。
- 私网基线：RTT 0.1–0.2 ms；iperf3 单机 4 流 TCP 约 15.8 Gbps。

## 2. 测试结果总览

| 测试组 | 用例数 | 通过 | 说明 |
|---|---:|---:|---|
| netns 集成套件（Phase 1+2+3） | 16 | 16 | 全部 PASS |
| API / 控制面 | 50+ | 全部符合预期 | 含鉴权、CRUD、上限、幂等、body 限制 |
| 真实网卡模块矩阵 | 17 | 17 | 黑名单/白名单/端口 ACL/L7/UDP/ICMP/全局限速/端口限速/conn_track/SYN proxy/TCP RST/Trust |
| 防护项目 + GeoIP（真实网卡） | 8 | 8 | DROP/PASS、block/allow/default_action |
| 持久化 / reload / kill -9 | 10 | 10 | 重启恢复、SIGHUP、XDP 优雅 detach/attach |
| Hub 连通性 | 5 | 5 | 节点注册、在线状态、每节点 token |
| 控制台 live E2E | 13 页 + 3 变更 | 2/3 变更 | 页面与 block/L7 变更通过；白名单 UI 变更因选择器超时未完成 |
| 边界 / 畸形包 / 分片 | 5 | 4 | 分片与畸形包安全；IPv6 仅有 link-local |
| 3.7 分钟混合 soak | 8 | 7 | 3580 万包，RSS/句柄稳定；1 项为脚本断言误报 |

## 3. 关键功能实测

### 3.1 netns 集成套件（16/16 PASS）

黑名单 DROP、TCP RST、全局限速、SYN Flood 挑战、Cookie 校验后合法握手、L7 命中/不命中、停止后流量恢复、SIGHUP reload、自适应封禁、GeoIP block、威胁情报、防护项目 DROP（8080 拦截 / 8081 不受影响）、SYN Cookie 正常握手直通、GeoIP allow（含分片）、GeoIP `default_action=drop`、conn_track（ICMP 不误伤）。

### 3.2 真实网卡模块矩阵（17/17 PASS）

| 用例 | 注入 | 结果 |
|---|---|---|
| 静态黑名单 DROP | atk1 pktgen 50k UDP | `blacklist_blocked +50,001`，`total_dropped +50,001` |
| 白名单优先于黑名单 | atk1 pktgen 50k，同时加白 + 加黑 | `total_passed +50,005`，`blacklist_blocked 0` |
| 端口 ACL drop | atk1 hping3 SYN → 8080 | `tcp_dropped +300` |
| 端口 ACL allow | atk1 hping3 SYN → 8081 | 基本无 XDP 丢弃（<50） |
| L7 命中 DROP | atk1 scapy 300×TCP `GET /` | `l7_blocked +300`，`total_dropped +300` |
| L7 不命中 PASS | atk1 scapy 300×TCP `POST /` | `l7_blocked 0`，`total_passed +305` |
| UDP Flood | 20k UDP | `udp_flood_blocked 1`，`blacklist_blocked 19,649` |
| ICMP Flood | hping3 `-1 --flood` 4s | `icmp_flood_blocked 1`，`blacklist_blocked 2,495,625` |
| 全局限速 | 20k UDP | `rate_limited 2`，`blacklist_blocked 19,652` |
| 端口维度限速 | 20k UDP → 80 | `udp_flood_blocked 19,842`，`blacklist_blocked 0` |
| conn_track | hping3 SYN flood 4s | `conn_track_blocked 2,244,478` |
| SYN Proxy / Cookie | hping3 SYN flood 4s | `syn_flood_blocked 2,401,629`（XDP_TX 挑战），`total_dropped 0` |
| TCP RST on DROP | 黑名单 + hping3 SYN | hping3 5/5 收到 RST 响应 |
| Trust Score | 100k PASS | `trust_trusted +1`（1/64 采样，符合设计） |

### 3.3 防护项目与 GeoIP（真实网卡，8/8 PASS）

- 项目 DROP：UDP/80 20k 包全部 DROP（`total_dropped +20,000`）。
- 项目 PASS：在 `udp_flood_enabled=true` 下 20k 包全部 PASS（`udp_flood_blocked 0`），验证项目优先级高于全局模块。
- GeoIP `block_countries=["ZZ"]` + atk1→ZZ：`geoip_blocked +20,001`。
- GeoIP `allow_countries=["ZZ"]` + `default_action="drop"`：atk1 20k 包全部 PASS。
- 把 CSV 改为 YY 后 `POST /api/geoip/reload`：`geoip_blocked +20,003`，验证 reload 后 allow miss → default drop。

### 3.4 持久化与故障恢复（10/10 PASS）

- 重启后黑名单、L7 指纹、防护项目全部从 `/var/lib/eshield/rules.redb` 恢复。
- SIGHUP reload 可新增/移除静态黑名单。
- `kill -9` 后进程消失、XDP 程序自动 detach；重新启动后 XDP 重新 attach，`/healthz` 正常。
- CLI `status/block/unblock/reload/check` 均可用（`status` 输出为中文，脚本断言误报一次）。

### 3.5 Hub（5/5 PASS）

- atk3 启动 `eshield-hub --bind 0.0.0.0:9930 --token hub-test`。
- 防御端配置 `[hub] enabled=true, urls=["http://172.23.83.41:9930"], node_name="defense-01"`。
- `/api/hub/status` 显示 `connected=true`、`active_url` 指向 Hub；Hub `/api/v1/nodes` 返回 `defense-01 online`。
- 本轮仅做连通性/注册冒烟，**策略下发、tombstone、冲突合并未在真实三节点上覆盖**（netns/单元测试覆盖了部分逻辑）。

### 3.6 控制台 live E2E

- 通过 SSH 隧道 `ssh -L 8720:127.0.0.1:8720 root@47.238.242.131` 打开控制台，顶栏显示「实时」。
- 总览 6 KPI、11 个导航项；攻击/包日志/审计/模块/访问控制/L7/项目/GeoIP/规则/设置全部渲染，无 page error。
- 通过 UI 完成：封禁 IP（写入成功，`GET /api/blacklist` 可见）、切换 L7 模块（`l7_scan_enabled` 变化）、新增 L7 指纹（`GET /api/l7-patterns` 可见）。
- 白名单新增的 UI 自动化因 Playwright 选择器超时未完成（API 侧白名单 CRUD 已通过）。

### 3.7 边界与稳健性

- 分片：2000 字节 UDP 分片 205 个包全部 PASS，`udp_flood_blocked 0`，符合「分片不参与 Flood 统计」的设计。
- 畸形包：`ihl=3`、`dataofs=0` 等 40 个畸形 TCP 包后，进程存活、`/healthz` 正常。
- API 上限：L7 >8 拒绝、mask 长度不匹配拒绝、port ACL >32 拒绝、body >1 MiB 返回 413。
- IPv6：eth0 仅有 `fe80::/64` link-local，无全局 IPv6，**全局 IPv6 攻击未覆盖**。
- 批量黑名单：200 条 `duration_s=30` 写入后 GET 可见 165 条，差额为 30 秒内自然过期，非缺陷。

### 3.8 混合 soak（3.7 分钟）

- atk1 循环 pktgen 200k/轮，期间每 15s 写 API、每 45s SIGHUP；共处理 **35,800,315 包**（约 162k pps 含间隔）。
- eShield RSS 48,652–48,768 KB（漂移 116 KB）、fd 38–38、进程存活、XDP 保持 attach；管理请求全程可用。
- 尚不足以证明 6h/24h 长稳，但短时无内存/句柄增长。

## 4. 发现的问题

### 4.1 动态白名单未纳入 `ControlState.whitelist`

- 现象：`POST /api/whitelist {"cidr":"203.0.113.0/24"}` 返回 200，数据面确实生效，但 `GET /api/whitelist` 看不到该条目；`POST /api/config/reload` 后该动态条目仍然在数据面生效（未被重置）。
- 机制：`ControlState::allow_cidr_raw` 只写 eBPF `WHITELIST_V4/V6`，没有把 `(key, prefix)` push 到 `self.whitelist`；`reload_config_file` 的 `apply_whitelist_map` 以 `self.whitelist` 为“旧集合”，因此动态条目既不会被 GET 列出，也不会在 reload 时被移除。
- 影响：`GET /api/whitelist` 与实际数据面不一致；reload 的“恢复配置文件状态”语义不成立。

### 4.2 端口 ACL 动作词表前后端不一致

- 后端 `PortAclItem::to_entry` 只接受 `allow` / `drop`；`accept` / `deny` 返回 400 `invalid action 'deny', expected allow/drop`。
- 控制台 mock（`console/src/api/mock.ts`）使用 `accept` / `deny`；`packaging/config.example.toml` 使用 `allow` / `drop`。
- 影响：真实数据面保存现有 `allow/drop` 条目没问题，但 mock/示例词表不统一，用户按 mock 填写会被拒绝。

### 4.3 generic XDP 在 virtio_net 上触发内核 WARNING

- `dmesg` 中 13 次：
  `netdevice: eth0: failed to disable GRO_HW!`
  `WARNING: net/core/dev.c:1857 at generic_xdp_install+0x119/0x180`
- 触发条件：`ESHIELD_XDP_MODE=skb` 在 `virtio_net` 上 attach generic XDP；XDP 功能正常，但内核被 taint（`Tainted: [W]`）。
- 影响：功能无碍；生产使用 SKB 模式需要注意该内核告警。native XDP 本环境未测。

### 4.4 `reset-token` 后 `config/reload` 不恢复 `api_token`

- `POST /api/auth/reset-token` 生成随机 token；随后 `POST /api/config/reload` 不会把 `api_token` 恢复为配置文件值（AuthState 只在启动时读取配置）。
- 现象：重置后用原 `eshield-test` 调 API 返回 401；重启进程后恢复。
- 影响：文档已说明部分配置需重启，但该行为容易误判为 reload 失败。

### 4.5 `/api/config` 的 `l7_scan.enabled` 与 `l7_scan_enabled` 不一致

- 通过 `PATCH {"l7_scan_enabled": true}` 启用 L7 后，`GET /api/config` 的 `l7_scan_enabled=true`，但 `l7_scan.enabled` 仍为 `false`。
- 数据面以 `l7_scan_enabled` 为准，功能正常；但配置快照存在两个语义重复的字段，容易误读。

## 5. 未覆盖 / 受限项

- 绝对线速、PPS 上限、native XDP 与 SKB 对照（本轮按要求不测基线极限）。
- 真实多节点 Hub 策略下发/撤回/tombstone/冲突合并。
- 全局 IPv6 攻击（测试网仅有 link-local）。
- 伪造源 IP 攻击（云 VPC 源地址校验，未验证可通过）。
- 6h/24h 长稳；本轮仅 3.7 分钟 soak。
- TUI 交互、多内核版本（5.10/6.x）验证。
- 控制台白名单新增 UI 的自动化选择器需完善。

## 6. 结论与建议

- **功能面**：v0.4.7 的数据面模块、控制面 API、CLI、持久化、故障恢复、Hub 连通性与控制台 live 渲染均按预期工作；实网卡上的黑/白名单、端口 ACL、L7、Flood、限速、conn_track、SYN Cookie、TCP RST、Trust、防护项目与 GeoIP 均验证通过。
- **优先级 P0**：修复 4.1（动态白名单纳入 `ControlState.whitelist`，并明确 reload 是否清理动态项）与 4.2（后端兼容 `accept/deny` 别名或统一前端 mock 为 `allow/drop`）。
- **优先级 P1**：明确 4.4 reload 对 `api_token` 的语义（更新 AuthState 或在文档/响应中显式说明）；统一 4.5 的 L7 双字段。
- **优先级 P2**：记录 4.3 的内核告警并评估 native XDP；补 Hub 策略下发与 IPv6 环境。
