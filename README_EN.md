# eShield

A host-level CC / L3-L4 network defense shield powered by **eBPF/XDP**.

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[中文 README](README.md)

---

## Table of Contents

- [Introduction](#introduction)
- [Performance & Capabilities](#performance--capabilities)
  - [Performance](#performance)
  - [Attacker Resource Cost](#attacker-resource-cost)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
- [Configuration & Usage](#configuration--usage)
- [Observability](#observability)
- [API Overview](#api-overview)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Positioning & Limitations](#positioning--limitations)
- [Documentation](#documentation)
- [License](#license)

---

## Introduction

eShield runs a Rust/Aya eBPF program on the Linux XDP hook to drop malicious traffic before it enters the kernel networking stack. The userspace control plane is built with Rust, Tokio, and axum, providing a Web Dashboard, REST API, CLI, TUI, audit log, persistence, and alerting.

Compared with traditional solutions such as iptables/nftables, eShield makes filtering decisions at the NIC driver layer, delivering lower latency, higher packet-processing throughput, and more accurate detection of CC / slow-connection-exhaustion attacks.

---

## Performance & Capabilities

### Performance

- **Kernel-space packet processing**: Filtering logic runs directly in eBPF/XDP without traversing the userspace network stack, eliminating context switches and data copies.
- **Microsecond-level latency**: Normal traffic only pays for an eBPF map lookup and rule match, typically adding less than 1 µs of latency.
- **High throughput**: In a single-core veth test environment, the XDP PASS path reaches approximately **240K pps**; the XDP DROP path can match or even beat the baseline because packets are dropped before the protocol stack is entered. On physical NICs with multi-queue/RSS, throughput scales to millions of pps.
- **Low overhead**: eBPF programs are JIT-compiled to native machine code; CPU usage grows linearly with traffic but with a very low slope. Packets that hit the blacklist or ACL are dropped at the earliest possible stage.
- **Single static binary**: Statically linked with musl; only the `eshield` executable is required, with no extra runtime dependencies.

> See [docs/benchmark.md](docs/benchmark.md) for detailed benchmark methodology.

### Attacker Resource Cost

Because eShield intercepts traffic at the earliest possible point, attackers must pay real costs to exert effective pressure:

- **Real bandwidth**: Every dropped packet consumes actual egress bandwidth from the attacker. Rate limiting and blacklisting drop packets instantly, so they never consume backend bandwidth.
- **Real source IPs**: Blacklists, GeoIP, threat intelligence, and the adaptive threshold engine all accumulate per source IP. Attackers need a large, distributed, and rotatable pool of real IPv4/IPv6 addresses to sustain an attack.
- **Full protocol-stack interaction**: The SYN Cookie proxy forces every spoofed source to complete a full three-way handshake. The JS Challenge requires a browser to execute JavaScript and return the correct answer. WAF rules only allow traffic that matches legitimate request signatures. Bypassing these mechanisms requires a real TCP/IP stack, a browser environment, or significant compute resources.
- **Continuous effort and compute**: The adaptive engine automatically escalates block duration for repeat offenders. Attackers must constantly vary signatures, IP ranges, and attack patterns, which is far more expensive than the defense-side cost.

In short, eShield tilts the offense/defense cost ratio in favor of the defender: a single eBPF map lookup on the defense side can neutralize a complete network packet, a real source address, and a protocol interaction on the attacker side.

---

## Core Features

| Feature | Description |
|---|---|
| eBPF/XDP early filtering | Packet processing happens at the NIC driver layer, with much lower latency than iptables/nftables. |
| CIDR whitelist | LPM-Trie based whitelist supporting IPv4/IPv6 CIDRs. |
| Dynamic blacklist | LRU hash for dynamic blacklisting with automatic expiry. |
| Per-IP rate limiting | Exponential-decay sliding-window rate limiting per source IP. |
| UDP / ICMP flood protection | Per-IP rate suppression for UDP and ICMP/ICMPv6 floods. |
| Protocol/port ACLs | Supports `tcp`/`udp`/`icmp`/`icmpv6`/`any`, ports, ranges, or `any`, with `allow`/`drop` actions. |
| SYN Cookie proxy | SYN Cookie proxy for IPv4 TCP SYN flood mitigation; legitimate ACKs are allowed after validation. |
| HTTP WAF rule engine | Inspects the first TCP packet, matching method, path_prefix, host, user_agent, and body_prefix. |
| JS Challenge | WAF `challenge` action intercepts requests and temporarily allowlists clients that pass `/challenge`. |
| GeoIP / ASN filtering | Allow or block by country or ASN via custom CSV CIDR lists. |
| Threat intel integration | Periodic synchronization of custom URL feeds to automatically block known malicious IPs. |
| Lightweight L7 fingerprint scan | Inspects the first 64 bytes of TCP payload and drops on pattern match. |
| Adaptive threshold engine | Escalates repeat offenders to longer block durations automatically. |
| Protection projects | Group policies by protocol + port + target IP; persisted in the control plane and managed via Dashboard/API. |
| Runtime control | REST API + Web Dashboard + CLI + TUI for real-time toggles and tuning. |
| Config hot reload | Reload configuration via `SIGHUP` or `systemctl reload` without restart. |
| Auth / audit / persistence | Optional Bearer token, audit log, and dynamic rule persistence with redb. |
| Observability | Prometheus `/metrics`, JSON stats, audit SSE, top attackers. |

> **About protection projects**: In the current version, protection projects are loaded, validated, persisted, and exposed via the Dashboard/API. Due to the XDP verifier's 512-byte combined stack limit, per-project packet matching in the eBPF data path is not yet enabled; global defense modules remain active.

---

## Architecture

```text
┌─────────────────────────────────────────────────────────────┐
│ Management Plane                                            │
│ Web Dashboard (axum) │ TUI (ratatui) │ CLI (clap)          │
└──────────────────────────────┬──────────────────────────────┘
                               │ REST API / Config Watch
┌──────────────────────────────▼──────────────────────────────┐
│ Control Plane — Rust userspace                              │
│ Config │ Event Consumer │ Adaptive Threshold │ Persistence │
└──────────────────────────────┬──────────────────────────────┘
                               │ BPF Maps / Ring Buffer
┌──────────────────────────────▼──────────────────────────────┐
│ Data Plane — eBPF/XDP kernel-space                          │
│ Parse → Whitelist → Port ACL → GeoIP → SYN Proxy → UDP/ICMP │
│ Flood → L7 Scan → WAF → Rate Limit → Blacklist → Decision   │
└─────────────────────────────────────────────────────────────┘
```

See [docs/architecture.md](docs/architecture.md) for detailed design.

---

## Quick Start

### Requirements

- Linux kernel >= **5.10** with **BTF** enabled:
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
- root or capabilities: `CAP_BPF`, `CAP_NET_ADMIN`, `CAP_NET_RAW`, `CAP_PERFMON`, `CAP_IPC_LOCK`
- Rust >= 1.70 (nightly + bpf target)
- LLVM / clang (required by Aya for compiling eBPF)

> **Windows developers**: The Aya userspace code relies on Linux-specific APIs, so you **cannot build or run eShield directly on Windows**. Use WSL2, a VM, or a Linux cloud host.

### One-line install

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

Pin a version:

```bash
VERSION=0.2.0 curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo VERSION=0.2.0 bash
```

### Build from source

```bash
sudo bash scripts/install.sh --build
```

This will:
1. Compile the eBPF program with the nightly toolchain
2. Build a static musl userspace binary
3. Install `eshield` to `/usr/local/bin`
4. Create the default config `/etc/eshield/config.toml`
5. Install and enable the systemd service

### Service management

```bash
sudo systemctl status eshield
sudo systemctl start eshield
sudo systemctl stop eshield
sudo systemctl restart eshield
sudo systemctl reload eshield   # SIGHUP hot reload
sudo journalctl -u eshield -f
```

---

## Configuration & Usage

### CLI commands

```bash
# Start the daemon
sudo eshield start --config /etc/eshield/config.toml

# Show status (CLI runs locally, no token required)
eshield status

# Block an IP in real time (0 = permanent)
eshield block 192.0.2.1 --duration 300

# Unblock an IP
eshield unblock 192.0.2.1

# Reload the config file
eshield reload

# Validate the config file
eshield check --config /etc/eshield/config.toml

# Launch the TUI dashboard
eshield tui

# Use a remote API endpoint
eshield status --endpoint http://eshield-host:8443
eshield block 192.0.2.1 --endpoint http://eshield-host:8443

# Reset the console access token (local CLI does not need the old token)
eshield reset-token
```

### Authentication

- When `api_token` is not set, external Web access is anonymous by default. Once set, external access to the Dashboard, `/api/*`, and `/metrics` must include `Authorization: Bearer <token>`.
- The CLI runs locally with source address `127.0.0.1/::1`, so it automatically bypasses token checks and does not need `--token`.

### Configuration file

Default path `/etc/eshield/config.toml`:

```toml
# Network interface for attaching XDP
interface = "eth0"

log_level = "info"          # trace/debug/info/warn/error
log_json = false            # Output logs as JSON
ebpf_log_enabled = false    # eBPF kernel debug logging

udp_flood_enabled = false   # UDP flood protection
icmp_flood_enabled = false  # ICMP/ICMPv6 flood protection
tcp_reset_on_drop = false   # Reply TCP RST on dropped TCP connections

web_bind = "0.0.0.0:8443"   # Web / API / Prometheus bind address
# api_token = "changeme"    # Optional API authentication

store_path = "/var/lib/eshield/rules.redb"  # Dynamic rule store

# Alert webhook (optional)
# alert_webhook_url = "https://hooks.example.com/eshield"
alert_webhook_type = "generic"   # generic / slack / dingtalk / wecom
alert_threshold_dps = 1000
alert_cooldown_s = 60

# Whitelist CIDRs
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]

# Static blacklist (loaded at startup, permanent)
blacklist = ["192.0.2.1"]

[rate_limit]
enabled = true
threshold = 200             # Max packets per tick
tick_ms = 100               # Tick window
decay_num = 7
decay_den = 8               # Exponential decay factor
block_duration_s = 300      # Block duration after trigger

[syn_proxy]
enabled = false             # SYN Cookie proxy

[l7_scan]
enabled = false
patterns = [
    { pattern = "ATTACKER" },
]

[adaptive]
enabled = true
threshold = 10              # Hits in window
window_s = 5
block_duration_s = 300

[waf]
enabled = false
# action: drop / log / challenge
rules = [
    { name = "block-admin", enabled = true, priority = 1, action = "drop", match = { method = "GET", path_prefix = "/admin" } },
    { name = "challenge-secret", enabled = true, priority = 2, action = "challenge", match = { method = "GET", path_prefix = "/secret" } },
]

[challenge]
enabled = true              # Must be used together with waf challenge action
mode = "js"                 # js / 302 (only js is implemented currently)
ttl_s = 3600                # Temporary allowlist TTL

[geoip]
enabled = false
country_blocks_csv = "/etc/eshield/geoip_country.csv"
# asn_blocks_csv = "/etc/eshield/geoip_asn.csv"
block_countries = ["XX"]
# allow_countries = ["CN"]
# block_asns = [12345]
# allow_asns = []
default_action = "pass"

[threat_intel]
enabled = false
# [[threat_intel.feeds]]
# name = "abuseipdb"
# url = "https://api.abuseipdb.com/api/v2/blacklist"
# interval_s = 3600
# action = "drop"
# confidence = 80

# Protocol/port ACL
# [[port_acl]]
# protocol = "tcp"
# dport = "22"
# action = "allow"

# Protection projects (control-plane grouping)
# [[protection_projects]]
# name = "web-service"
# description = "Protect public HTTP service"
# protocol = "tcp"
# dport = "80"
# target_ips = ["10.0.0.10"]
# enabled_modules = ["rate_limit", "waf", "challenge"]
# action = "defend"   # pass / drop / defend
```

### Hot reload

After editing `/etc/eshield/config.toml`:

```bash
sudo systemctl reload eshield
# or
sudo kill -HUP $(pidof eshield)
```

When the log shows `config reloaded successfully`, the change is active without restart.

---

## Observability

### Web Dashboard

After starting the service, open:

```
http://<host>:8443/
```

The Dashboard shows real-time packet statistics, defense-module hits, top attackers, audit logs, and live control forms for:

- Blocking / unblocking IPv4/IPv6
- Allowing / removing IPv4/IPv6 CIDR
- Enabling/disabling modules and tuning rate-limit parameters
- Toggling eBPF debug logging and TCP RST replies
- Managing WAF rules, port ACLs, L7 patterns, GeoIP, and threat-intel feeds
- Managing protection-project groups
- Entering the API token (when authentication is enabled)
- One-click config reload

### Prometheus metrics

```
http://<host>:8443/metrics
```

Key metrics exposed:

- `eshield_dropped_total`
- `eshield_passed_total`
- `eshield_blacklist_blocked_total`
- `eshield_rate_limited_total`
- `eshield_syn_flood_blocked_total`
- `eshield_l7_blocked_total`
- `eshield_adaptive_blocked_total`
- `eshield_udp_flood_blocked_total`
- `eshield_icmp_flood_blocked_total`
- `eshield_waf_blocked_total`
- `eshield_geoip_blocked_total`
- `eshield_challenge_issued_total`
- `eshield_dropped_by_protocol_total{protocol="tcp|udp|icmp|other"}`
- `eshield_dropped_by_port_total{port="..."}`
- `eshield_source_dropped_total{ip="..."}`
- `eshield_event_consumer_duration_us_*`
- `eshield_map_max_entries{name="..."}`
- `eshield_map_entries{name="..."}`

### JSON stats endpoint

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8443/api/stats | jq
```

### TUI dashboard

```bash
eshield tui
```

Displays total drops, rule hits, and top attackers; press `q` to quit.

### Audit log

- `GET /api/audit` queries audit events, supporting `limit`, `ip`, `action`, `from`, and `to` filters.
- `GET /api/audit/stream` pushes audit events in real time via SSE.

---

## API Overview

| Endpoint | Methods | Description |
|---|---|---|
| `/healthz` | GET | Health check |
| `/ready` | GET | Readiness check |
| `/login` | GET | Console login page |
| `/challenge` | GET | JS challenge page |
| `/blocked` | GET | 403 block example page |
| `/api/challenge/pass` | POST | Submit challenge answer |
| `/api/auth/login` | POST | Console login verification |
| `/api/auth/check` | GET | Login status check |
| `/api/auth/reset-token` | POST | Reset access token (external requests require auth; local CLI can call directly) |
| `/` | GET | Web Dashboard |
| `/api/stats` | GET | Runtime stats |
| `/api/config` | GET, PATCH | Read/patch runtime config |
| `/api/config/reload` | POST | Reload config from file |
| `/api/protection-modules` | GET | Protection module list and status |
| `/api/blacklist` | POST, DELETE | Block/unblock IP |
| `/api/whitelist` | POST, DELETE | Allow/remove CIDR whitelist |
| `/api/audit` | GET | Audit log |
| `/api/audit/stream` | GET | Audit log SSE |
| `/api/metrics/series` | GET | Time-series metrics |
| `/api/metrics/attacker-series` | GET | Per-IP time series |
| `/api/waf/rules` | GET, POST | WAF rules CRUD |
| `/api/waf/rules/reorder` | POST | Reorder WAF rules |
| `/api/port-acl` | GET, POST | Port ACL |
| `/api/protection-projects` | GET, POST | Protection projects |
| `/api/l7-patterns` | GET, POST | L7 patterns |
| `/api/geoip/reload` | POST | Reload GeoIP CSV |
| `/api/threat-intel/sync` | POST | Trigger threat-intel sync |
| `/metrics` | GET | Prometheus metrics |

> For external access to protected endpoints, include `Authorization: Bearer <token>` when `api_token` is set. The local CLI automatically bypasses authentication.

---

## Testing

### Unit tests

```bash
cargo test --workspace --exclude eshield-ebpf
```

### Integration tests

Requires root. Creates a veth pair in a network namespace and runs multiple scenarios:

```bash
sudo bash ./tests/netns_test.sh
```

Covers: blacklist, TCP RST on drop, rate limiting, SYN flood, L7 fingerprint, HTTP WAF, JS challenge, service-stop restoration, SIGHUP reload, adaptive threshold, GeoIP/ASN, and threat intel.

### Benchmarks

```bash
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash scripts/benchmark.sh
```

Tune via environment variables:

```bash
PACKETS=500000 INTERVAL=u1 sudo -E bash scripts/benchmark.sh
```

See [docs/benchmark.md](docs/benchmark.md) for details.

---

## Project Structure

```text
.
├── eshield/            # Userspace control plane
│   ├── src/main.rs     # CLI + daemon startup
│   ├── src/control.rs  # eBPF map ops / runtime policy / SIGHUP reload
│   ├── src/web.rs      # REST API + Web Dashboard
│   ├── src/dashboard.html
│   ├── src/login.html
│   ├── src/challenge.html
│   ├── src/blocked.html
│   ├── src/tui.rs      # TUI dashboard
│   ├── src/config.rs   # Config model and validation
│   ├── src/store.rs    # redb persistence
│   ├── src/adaptive.rs # Adaptive threshold engine
│   ├── src/audit.rs    # Audit log
│   ├── src/geoip.rs    # GeoIP/ASN loading
│   ├── src/threat_intel.rs
│   └── ...
├── eshield-ebpf/       # Kernel eBPF/XDP data plane
├── eshield-common/     # Shared kernel/userspace types
├── xtask/              # Build task helpers
├── scripts/            # install.sh / uninstall.sh / benchmark.sh
├── tests/              # Integration test scripts
├── docs/               # Architecture, deployment, dev env, API, benchmark docs
├── packaging/          # systemd service, deb/rpm configs, sample configs
├── README.md
├── README_EN.md
└── LICENSE
```

---

## Positioning & Limitations

- **Host-level CC defense shield**: Targets CC / slow attacks that exhaust CPU or connections rather than raw bandwidth.
- **Not a DDoS silver bullet**: Terabit-scale bandwidth floods require upstream cloud mitigation; eShield cannot exceed physical network limits.
- **SYN Cookie proxy**: Currently IPv4 TCP only; all SYNs are challenged when enabled.
- **WAF & L7 scan**: Inspect only the first TCP packet; TCP reassembly is not supported.
- **Windows**: Cannot build or run directly; use a Linux environment.
- **Protection projects**: Currently a control-plane policy grouping; per-packet enforcement in eBPF is not yet enabled.

---

## Documentation

- [Architecture](docs/architecture.md)
- [Deployment](docs/deployment.md)
- [Development environment](docs/dev-linux.md)
- [Operations](docs/operations.md)
- [API](docs/api.md)
- [Benchmarks](docs/benchmark.md)

---

## License

Apache-2.0
