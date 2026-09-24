# eShield

[中文](README.md) | English

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

eShield is a host-level L3-L4 network protection system built on eBPF/XDP. It drops SYN flood, UDP flood, ICMP flood, scanning, and connection-exhaustion traffic before packets enter the Linux network stack. The project is implemented in Rust and includes an eBPF data plane, a userspace control plane, a distributed policy hub, a web console, a CLI, and a TUI.

## Table of Contents

- [1. Overview](#1-overview)
- [2. Capabilities](#2-capabilities)
- [3. Architecture](#3-architecture)
- [4. Requirements](#4-requirements)
- [5. Build and Installation](#5-build-and-installation)
- [6. Quick Start](#6-quick-start)
- [7. Configuration](#7-configuration)
- [8. Runtime Operations](#8-runtime-operations)
- [9. Distributed Hub](#9-distributed-hub)
- [10. Observability](#10-observability)
- [11. Performance](#11-performance)
- [12. Testing](#12-testing)
- [13. Project Structure](#13-project-structure)
- [14. Security Boundaries and Limitations](#14-security-boundaries-and-limitations)
- [15. Documentation](#15-documentation)
- [16. License](#16-license)

## 1. Overview

eShield attaches filtering logic to the XDP hook at the NIC driver layer. Packets are parsed, matched, and dropped before they reach the kernel network stack, preventing malicious traffic from consuming stack, connection-table, and application resources.

The system is designed as a **host-level first line of defense** for single hosts, edge nodes, origin servers, game servers, and internal services. It does not replace cloud scrubbing, CDN protection, or carrier-grade DDoS mitigation, and it cannot exceed the physical link bandwidth.

Components:

| Component | Description |
|---|---|
| `eshield-ebpf` | XDP/eBPF data plane for per-packet parsing, rule matching, dropping, TCP RST, and SYN cookie responses. |
| `eshield` | Userspace control plane for configuration, API, web console, TUI, persistence, audit, alerting, and Hub synchronization. |
| `eshield-common` | Shared structs, constants, and pure functions used by both data and control planes. |
| `eshield-hub` | Distributed policy aggregation service for node registration, policy sharing, and per-node tokens. |
| `xtask` | Build task wrapper that pins the eBPF toolchain and target. |

## 2. Capabilities

### 2.1 Data Plane

| Capability | Description |
|---|---|
| eBPF/XDP early filtering | Drop decisions are made at the NIC driver layer without entering the kernel network stack. |
| CIDR allowlist | LPM trie based, supports IPv4/IPv6; allowlisted traffic passes as early as possible. |
| Dynamic blocklist | LRU hash based, supports permanent and time-limited blocks with automatic expiry. |
| Per-IP rate limiting | Exponentially decaying sliding window for burst connection and request detection. |
| Per-destination-port rate limiting | Protocol and destination-port based limiting to reduce source-IP rotation bypass. |
| UDP/ICMP flood protection | Per-IP and per-port rate suppression for connectionless traffic. |
| Port/protocol ACL | Supports `tcp`, `udp`, `icmp`, `icmpv6`, `any`, port ranges, and wildcards. |
| SYN cookie proxy | Returns SYN-ACK cookies for IPv4 TCP SYN floods and admits clients after ACK validation. |
| TCP RST response | Replies with RST for dropped TCP connections to reduce client retransmission buildup. |
| GeoIP/ASN filtering | Country/ASN allow or block based on CSV CIDR lists with configurable `default_action`. |
| Threat intelligence | Periodic synchronization of external feeds into blocklists or allowlists. |
| L7 fingerprint scanning | Inspects the first TCP payload bytes to identify scanning and probing behavior. |
| Connection tracking / CC defense | Optional half-open connection counter; only SYN/ACK/RST access the map. |
| Protection projects | Policy groups by destination IPv4, port, and protocol with PASS, DROP, and DEFEND actions. |
| Adaptive thresholds | Time-window event aggregation with extended blocking for repeat offenders. |
| Trust Score | Bidirectional IP reputation; PASS increases score, DROP decreases it, rate thresholds are modulated. |
| Danger Signal | Global defense level and threshold adjustment based on system load and attack intensity. |
| Packet sampling log | Sampled DROP packet reporting for forensics and troubleshooting. |

### 2.2 Control Plane and Operations

| Capability | Description |
|---|---|
| Web console | Native ES modules and modular CSS, system light/dark theme, text-only navigation, command palette. |
| CLI and TUI | `eshield start/status/block/unblock/reload/check/tui/reset-token`. |
| Configuration reload | Reload through `SIGHUP` or `systemctl reload` without restarting XDP. |
| Authentication | Optional Bearer token; loopback requests bypass token validation. |
| Persistence | Dynamic rules and time-series metrics are stored in redb and restored after restart. |
| Audit | Memory or JSON Lines audit backend with SSE streaming and CSV export. |
| Metrics | Prometheus `/metrics` and JSON `/api/stats`. |
| Alerting | Webhook alerts with threshold and cooldown configuration. |
| Distributed policy | Hub aggregates policies across nodes; supports master token and per-node tokens. |
| Kernel compatibility | Pinned `nightly-2026-07-31` and `bpf-linker 0.10.4`; `ESHIELD_XDP_MODE=skb` for virtual NICs. |

## 3. Architecture

```text
┌──────────────────────────────────────────────────────────────┐
│ Management                                                   │
│ Web console (axum) │ CLI (clap) │ TUI (ratatui)              │
└──────────────────────────────┬───────────────────────────────┘
                               │ REST API / SSE / config watch
┌──────────────────────────────▼───────────────────────────────┐
│ Control plane (Rust userspace)                               │
│ Config │ Events │ Adaptive │ Persistence │ Metrics │ Audit   │
└──────────────────────────────┬───────────────────────────────┘
                               │ BPF maps / ring buffer
┌──────────────────────────────▼───────────────────────────────┐
│ Data plane (eBPF/XDP)                                        │
│ Parse → Allowlist → Port ACL → Blocklist → Projects → GeoIP  │
│ → Connection tracking → TCP (SYN cookie/flood) → UDP/ICMP    │
│ → L7 fingerprint → Rate limit → Trust/stats → Decision       │
└──────────────────────────────────────────────────────────────┘
```

Packet journey, BPF map layout, and state machines are documented in [docs/architecture.md](docs/architecture.md).

## 4. Requirements

### 4.1 Runtime

- Linux kernel 5.10 or later with BTF enabled:

  ```bash
  ls /sys/kernel/btf/vmlinux
  ```

- root privileges or the following capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_PERFMON`, `CAP_IPC_LOCK`.
- An XDP-capable NIC. SKB generic mode is recommended for virtual NICs.

### 4.2 Build

- Stable Rust toolchain for userspace and Hub builds.
- Nightly toolchain pinned to `nightly-2026-07-31` for eBPF builds, with `rust-src` and `clippy` components.
- `bpf-linker 0.10.4`.
- clang/LLVM, libelf, and musl toolchain.
- `x86_64-unknown-linux-musl` Rust target.

The build toolchain can be overridden with environment variables:

| Variable | Purpose |
|---|---|
| `ESHIELD_EBPF_TOOLCHAIN` | Override the nightly toolchain used for eBPF builds. |
| `ESHIELD_XDP_MODE` | Set to `skb` or `generic` to force SKB generic attach mode. |
| `ESHIELD_INTERFACE` | Override the interface from the configuration file. |

Windows hosts cannot build or run the project directly. Build and test on WSL2, a Linux virtual machine, or a Linux cloud host.

## 5. Build and Installation

### 5.1 Installer

```bash
sudo bash scripts/install.sh --build
```

The installer performs the following steps:

1. Build the eBPF program with the pinned nightly toolchain.
2. Build the userspace binary with the musl target.
3. Install `eshield` to `/usr/local/bin`.
4. Create `/etc/eshield/config.toml`.
5. Install and enable the systemd service.

### 5.2 Manual Build

```bash
export ESHIELD_EBPF_TOOLCHAIN=nightly-2026-07-31

cargo xtask build-ebpf
cargo build --package eshield --target x86_64-unknown-linux-musl --release
cargo build --package eshield-hub --release
```

Artifacts:

```text
target/x86_64-unknown-linux-musl/release/eshield
target/release/eshield-hub
target/bpfel-unknown-none/release/eshield
```

The eBPF object is embedded into the userspace binary through `include_bytes_aligned!`, so deployment only requires the userspace executable.

## 6. Quick Start

### 6.1 Minimal Configuration

```toml
interface = "eth0"
web_bind = "0.0.0.0:8720"
api_token = "replace-with-a-random-token"

whitelist = ["10.0.0.0/8"]
blacklist = []

[rate_limit]
enabled = true
threshold = 200
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 300

[syn_proxy]
enabled = true

[conn_track]
enabled = false
threshold = 20
window_ms = 10000
```

A complete example is available in [packaging/config.example.toml](packaging/config.example.toml).

### 6.2 Start

```bash
sudo eshield start --config /etc/eshield/config.toml
```

The console listens on `http://<host>:8720/` by default. When `api_token` is not set, the system generates a random token and prints its prefix in the log. Use `eshield reset-token` to rotate it.

### 6.3 systemd

```bash
sudo systemctl start eshield
sudo systemctl status eshield
sudo systemctl stop eshield
sudo systemctl reload eshield
sudo journalctl -u eshield -f
```

`reload` sends `SIGHUP` and reloads the configuration without detaching XDP.

### 6.4 Virtual NIC Test Mode

Native XDP_TX on veth and similar virtual NICs can trigger kernel issues. Use SKB mode in test environments:

```bash
ESHIELD_XDP_MODE=skb sudo eshield start --config /etc/eshield/config.toml
```

Integration test scripts use `ESHIELD_TEST_XDP_MODE=skb` to run all instances in SKB mode.

## 7. Configuration

The default configuration path is `/etc/eshield/config.toml`.

| Section / field | Purpose |
|---|---|
| `interface` | NIC used for XDP attach. |
| `web_bind` | Web/API listen address, default `0.0.0.0:8720`. |
| `api_token` | Bearer token; a random token is generated when unset. |
| `whitelist` / `blacklist` | Static CIDR allowlist and permanent blocklist loaded at startup. |
| `[rate_limit]` | Per-IP exponentially decaying rate limit and block duration. |
| `[port_rate_limit]` | Fixed-window rate limit by protocol and destination port. |
| `[syn_proxy]` | IPv4 SYN cookie proxy switch. |
| `[udp_flood]` / `[icmp_flood]` | Connectionless flood protection switches. |
| `[l7_scan]` | TCP first-payload fingerprint matching. |
| `[adaptive]` | Automatic blocking window and threshold for repeat offenders. |
| `[geoip]` | Country/ASN allow or block based on CSV CIDR lists. |
| `[threat_intel]` | External threat intelligence feed synchronization. |
| `[trust_score]` | Bidirectional IP reputation and divisor configuration. |
| `[danger_signal]` | System danger level monitoring and threshold adjustment. |
| `[conn_track]` | Optional connection tracking and half-open CC defense. |
| `[port_acl]` | Port and protocol allow/drop rules. |
| `[protection_projects]` | Protection groups by destination IPv4, port, and protocol. |
| `[packet_log]` | DROP packet sampling log. |
| `[hub]` | Distributed Hub synchronization. |
| `timeseries_retention_days` | Time-series retention period. |
| `[audit]` | Audit backend and file rotation. |
| `[alert]` | Webhook address, type, threshold, and cooldown. |

Constraints:

- `protection_projects.target_ips` must not be empty and must contain at least one IPv4 target. The data plane matches exact IPv4 addresses; CIDRs are expanded by the control plane with a minimum prefix of `/24`. Project policy capacity is 8192 entries.
- `port_acl` supports up to 32 entries and `l7_scan.patterns` supports up to 8 entries. These limits satisfy the kernel 7.0 verifier instruction processing limit.
- `conn_track.threshold` and `conn_track.window_ms` must be greater than zero.

## 8. Runtime Operations

### 8.1 CLI Commands

```bash
# Start the daemon
sudo eshield start --config /etc/eshield/config.toml

# Local status
eshield status

# Block an IP; duration 0 means permanent
eshield block 192.0.2.1 --duration 300

# Unblock an IP
eshield unblock 192.0.2.1

# Reload configuration
eshield reload

# Validate configuration
eshield check --config /etc/eshield/config.toml

# Start TUI
eshield tui

# Remote API
eshield status --endpoint http://eshield-host:8720
eshield block 192.0.2.1 --endpoint http://eshield-host:8720

# Rotate console token
eshield reset-token
```

### 8.2 Authentication

- When `api_token` is configured, the dashboard, `/api/*`, and `/metrics` require `Authorization: Bearer <token>`.
- Local CLI requests from loopback addresses bypass token validation.
- The web console provides a `/login` page that stores the token in a cookie for browser sessions.

### 8.3 Reload

```bash
sudo systemctl reload eshield
sudo kill -HUP $(pidof eshield)
```

## 9. Distributed Hub

`eshield-hub` aggregates and distributes policies across nodes.

### 9.1 Start the Hub

```bash
eshield-hub --bind 0.0.0.0:9930 --token "master-token"
```

A TLS termination layer such as nginx or Caddy should be deployed in front of the Hub in production.

### 9.2 Per-Node Tokens

```bash
eshield-hub --bind 0.0.0.0:9930 \
  --token "master-token" \
  --node-tokens-file /etc/eshield-hub/node-tokens
```

Each line in `node-tokens` uses the format `node_name:token`. Comment lines starting with `#` and empty lines are ignored. After a node token is authenticated, the Hub uses the authenticated node name for policy attribution and rate limiting, preventing `node_name` spoofing through request bodies. The master token remains compatible.

### 9.3 Node Configuration

```toml
[hub]
enabled = true
urls = ["https://hub.example.com:9930"]
node_name = "web-tier-01"
token = "node-token"
sync_pull_interval_s = 10
sync_push_interval_s = 5
sync_rules_enabled = true
```

Nodes retain local policy autonomy when the Hub is unavailable and retry synchronization automatically.

## 10. Observability

### 10.1 Web Console

The console is served at `http://<host>:8720/` by default. It uses a flat design that follows the system light/dark theme, text-only navigation, and no decorative icons.

Pages:

| Page | Content |
|---|---|
| Overview | All KPIs, traffic and drop trends, drop reasons, top attackers and ports, recent attacks. |
| Live Traffic | Sampled packet log, protocol/port filtering, hexadecimal payload view. |
| Attack Events | Event list, source IP detail drawer, block, allowlist, and unblock actions. |
| Protection Modules | Switches and parameters for every protection module, applied immediately. |
| Protection Rules | Blocklist, allowlist, port ACL, L7 fingerprints, protection projects, threat intelligence. |
| Security Operations | Quick block, CIDR allowlist, static blocklist and allowlist management. |
| Audit Log | Operation audit, filters, pagination, SSE stream, CSV export. |
| Cluster | Hub connection status, node list, policy synchronization, per-node tokens. |
| Settings | Runtime information, alert configuration, token management, raw configuration view. |

Console shortcuts:

- `Ctrl/Cmd+K`: command palette for page navigation, search focus, and configuration reload.
- `g` sequences: `g o` overview, `g a` attacks, `g t` traffic, `g l` audit, `g p` modules, `g r` rules, `g s` security, `g c` cluster, `g ,` settings.
- `/`: focus global search.
- Theme follows `prefers-color-scheme`.

### 10.2 Prometheus Metrics

```text
http://<host>:8720/metrics
```

Primary metrics include `eshield_dropped_total`, `eshield_passed_total`, `eshield_blacklist_blocked_total`, `eshield_rate_limited_total`, `eshield_syn_flood_blocked_total`, `eshield_udp_flood_blocked_total`, `eshield_icmp_flood_blocked_total`, `eshield_geoip_blocked_total`, `eshield_conn_track_blocked_total`, and `eshield_dropped_by_protocol_total`.

### 10.3 JSON API

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8720/api/stats | jq
```

The full API reference is available in [docs/api.md](docs/api.md).

### 10.4 Audit

- `GET /api/audit`: query audit events with `limit`, `ip`, `action`, `from`, and `to`.
- `GET /api/audit/stream`: SSE stream.
- Audit backends include memory and JSON Lines files with size-based rotation.

### 10.5 TUI

```bash
eshield tui
```

## 11. Performance

### 11.1 Design Goals

- Normal traffic adds only a small number of eBPF map lookups and branches.
- Optional modules are disabled by default and skipped quickly when inactive.
- High-frequency write paths use sampling and batching to reduce map write amplification during attacks.
- Control-plane synchronization tasks are outside the per-packet path.

### 11.2 veth Large-Packet Throughput Benchmark

Environment: Linux kernel 7.0, 8 vCPU, netns + veth, `iperf3 -c <server> -t 5 -P 4` with large-packet TCP.

| Scenario | Throughput | Notes |
|---|---:|---|
| Baseline (no XDP) | 274.44 Gbps | veth memory-copy limit |
| Minimal XDP_PASS (native) | 12.83 Gbps | veth native XDP bottleneck |
| eShield PASS (native, no rules) | 11.85 Gbps | about -7.6% vs minimal program |
| Minimal XDP_PASS (SKB generic) | 124.62 Gbps | SKB generic is faster on veth |
| eShield PASS (SKB generic, no rules) | 112.30 Gbps | about -9.9% vs minimal program |
| eShield PASS (native, modules enabled, no DROP) | 11.81 Gbps | about -0.3% vs empty rules |

Conclusions:

- veth native XDP is the primary bottleneck in this benchmark. eShield adds approximately 7%-10% overhead relative to a minimal XDP_PASS program.
- With large-packet TCP, enabling rate limiting, Trust, connection tracking, and other modules adds less than 1% overhead.
- At 1500-byte packets, native mode processes approximately 1 Mpps and SKB generic mode approximately 9-10 Mpps.
- Small-packet, high-pps, and physical NIC line-rate figures require real NIC testing with `xdp-bench` or `pktgen`; the table above cannot be extrapolated.

### 11.3 High-Frequency Write Optimizations

| Path | Strategy |
|---|---|
| Trust PASS update | 1/64 sampled write with 64x weight compensation. |
| Trust DROP update | 1/16 sampled write for sources whose trust score is already zero. |
| Blacklist hit_count | 1/16 sampled write, adding 16 per sampled update. |
| TOP_ATTACKERS ranking | 1/16 sampled write, adding 16 per sampled update. |
| Blacklist-hit RingBuf events | Suppressed; counts are covered by global statistics and hit_count. |

Detailed methodology and data are available in [docs/benchmark.md](docs/benchmark.md).

## 12. Testing

### 12.1 Unit Tests

```bash
cargo test --workspace --exclude eshield-ebpf
```

### 12.2 Integration Tests

Integration tests require root privileges and run inside network namespaces. SKB mode is recommended for virtual NICs.

```bash
sudo ESHIELD_TEST_XDP_MODE=skb bash tests/netns_test.sh
sudo ESHIELD_XDP_MODE=skb bash tests/hub_node_test.sh
sudo ESHIELD_XDP_MODE=skb bash tests/full_attack_test.sh
```

Covered scenarios include blocklist, TCP RST response, rate limiting, SYN flood, SYN cookie challenge and recovery, UDP flood, ICMP flood, L7 fingerprints, SIGHUP reload, adaptive thresholds, GeoIP/ASN, threat intelligence, protection project DROP, GeoIP allowlist, IPv4 fragments, connection tracking half-open blocking, and Hub policy synchronization with per-node tokens.

### 12.3 Formatting and Static Analysis

```bash
cargo fmt --all -- --check
cargo clippy --workspace --exclude eshield-ebpf -- -D warnings
cargo +nightly-2026-07-31 clippy --package eshield-ebpf \
  --target bpfel-unknown-none -Z build-std=core -- -D warnings
```

## 13. Project Structure

```text
.
├── eshield/            # Userspace control plane, web console, CLI, TUI
├── eshield-ebpf/       # eBPF/XDP data plane
├── eshield-common/     # Shared structs, constants, and pure functions
├── eshield-hub/        # Distributed policy Hub
├── xtask/              # eBPF build tasks
├── scripts/            # Install, uninstall, benchmark, and release scripts
├── tests/              # Unit and integration test scripts
├── docs/               # Architecture, deployment, operations, API, benchmark, and development docs
├── packaging/          # systemd, example configuration, container, and orchestration files
├── README.md
├── README_EN.md
└── LICENSE
```

## 14. Security Boundaries and Limitations

- **Host-level protection**: designed for L3-L4 protection on a single host or edge node. Tbps-scale bandwidth exhaustion requires upstream scrubbing or carrier mitigation; eShield cannot exceed the physical link capacity.
- **Limited L7 capability**: the L7 module inspects only TCP first-payload fingerprints. It does not perform TCP segment reassembly and does not provide complete application-layer protection against HTTP floods, CC attacks, or slow attacks.
- **SYN cookie scope**: IPv4 TCP only, challenge mode, and only sources that exceed the configured threshold.
- **Protection project scope**: the data plane matches exact IPv4 addresses only. CIDRs are expanded by the control plane with a minimum prefix of `/24`. The project limit is 8192 entries.
- **Rule capacity limits**: `port_acl` supports up to 32 entries and `l7_scan.patterns` supports up to 8 entries due to the kernel 7.0 verifier instruction processing limit.
- **Virtual NIC limitation**: native XDP_TX on veth and similar virtual NICs can trigger kernel issues. Test environments should use `ESHIELD_XDP_MODE=skb`.
- **Platform limitation**: Windows is not supported. Kernels without BTF are not supported.
- **Missing physical NIC benchmarks**: current public benchmarks are based on veth. Physical NIC, multi-queue, small-packet pps, and latency figures must be measured in the target environment.

## 15. Documentation

| Document | Content |
|---|---|
| [docs/user-guide.md](docs/user-guide.md) | Operations and security user guide. |
| [docs/architecture.md](docs/architecture.md) | System architecture, packet journey, and BPF maps. |
| [docs/deployment.md](docs/deployment.md) | Binary, systemd, container, Kubernetes, and Hub deployment. |
| [docs/operations.md](docs/operations.md) | Daily operations, logs, alerting, backup, and troubleshooting. |
| [docs/dev-linux.md](docs/dev-linux.md) | Dependency installation, build, and local testing. |
| [docs/api.md](docs/api.md) | REST API endpoints, requests, and responses. |
| [docs/benchmark.md](docs/benchmark.md) | Benchmark methodology and data. |

## 16. License

Apache-2.0
