# eShield

[中文](README.md) | English

[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)

A host-level L3-L4 network scrubbing shield powered by **eBPF/XDP**, focused on defending against SYN/UDP/ICMP Flood, CC, and network-layer scanning attacks.

---

## Table of Contents

- [Introduction](#introduction)
- [Core Capabilities](#core-capabilities)
  - [Performance](#performance)
  - [Attacker Resource Cost](#attacker-resource-cost)
- [Core Features](#core-features)
- [Architecture](#architecture)
- [Quick Start](#quick-start)
  - [Requirements](#requirements)
  - [Build & Install](#build--install)
  - [Service Management](#service-management)
- [Configuration & Usage](#configuration--usage)
  - [CLI Commands](#cli-commands)
  - [Authentication](#authentication)
  - [Configuration File](#configuration-file)
  - [Hot Reload](#hot-reload)
- [Observability](#observability)
- [API & Documentation](#api--documentation)
- [Testing](#testing)
- [Project Structure](#project-structure)
- [Positioning & Limitations](#positioning--limitations)
- [License](#license)

---

## Introduction

eShield runs a Rust/Aya eBPF program on the Linux XDP hook to drop malicious traffic before it enters the kernel networking stack. The userspace control plane is built with Rust, Tokio, and axum, providing a Web Dashboard, REST API, CLI, TUI, audit log, persistence, and alerting.

Compared with traditional solutions such as iptables/nftables, eShield makes filtering decisions at the NIC driver layer, delivering lower latency, higher packet-processing throughput, and stronger mitigation of SYN/UDP/ICMP Flood and CC attacks.

---

## Core Capabilities

### Performance

- **Kernel-space packet processing**: Filtering logic runs directly in eBPF/XDP without traversing the userspace network stack, eliminating context switches and data copies.
- **Microsecond-level latency**: Normal traffic only pays for an eBPF map lookup and rule match, typically adding less than 1 µs of latency.
- **High throughput**: In a single-core veth test environment, the XDP PASS path reaches approximately **240K pps**; on physical NICs with multi-queue/RSS, throughput scales to millions of pps.
- **Low overhead**: eBPF programs are JIT-compiled to native machine code; packets that hit the blacklist or ACL are dropped at the earliest possible stage.
- **Single static binary**: Statically linked with musl; only the `eshield` executable is required, with no extra runtime dependencies.

> See [docs/benchmark.md](docs/benchmark.md) for detailed benchmark methodology.

### Attacker Resource Cost

Because eShield intercepts traffic at the earliest possible point, attackers must pay real costs to exert effective pressure:

- **Real bandwidth**: Every dropped packet consumes actual egress bandwidth from the attacker.
- **Real source IPs**: Blacklists, GeoIP, threat intelligence, and the adaptive threshold engine all accumulate per source IP.
- **Full protocol-stack interaction**: The SYN Cookie proxy forces every spoofed source to complete a full three-way handshake.
- **Continuous effort and compute**: The adaptive engine automatically escalates block duration for repeat offenders.

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
| TCP RST on drop | Immediately reply RST for dropped TCP connections to prevent retransmissions. |
| GeoIP / ASN filtering | Allow or block by country or ASN via custom CSV CIDR lists. |
| Threat intel integration | Periodic synchronization of custom URL feeds to automatically block known malicious IPs. |
| Lightweight L7 fingerprint scan | Inspect the first bytes of TCP payload and drop on pattern match. |
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
│ Flood → L7 Scan → Rate Limit → Blacklist → Decision         │
└─────────────────────────────────────────────────────────────┘
```

Detailed design, packet journey, and BPF Maps are documented in [docs/architecture.md](docs/architecture.md).

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

### Build & Install

```bash
sudo bash scripts/install.sh --build
```

This will:
1. Compile the eBPF program with the nightly toolchain
2. Build a static musl userspace binary
3. Install `eshield` to `/usr/local/bin`
4. Create the default config `/etc/eshield/config.toml`
5. Install and enable the systemd service

You can also download a prebuilt binary; see [docs/deployment.md](docs/deployment.md).

### Service Management

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

### CLI Commands

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
eshield status --endpoint http://eshield-host:8720
eshield block 192.0.2.1 --endpoint http://eshield-host:8720

# Reset the console access token (local CLI does not need the old token)
eshield reset-token
```

### Authentication

- When `api_token` is not set, external Web access is anonymous by default. Once set, external access to the Dashboard, `/api/*`, and `/metrics` must include `Authorization: Bearer <token>`.
- The CLI runs locally with source address `127.0.0.1/::1`, so it automatically bypasses token checks and does not need `--token`.

### Configuration File

Default path `/etc/eshield/config.toml`; a full example is available at [packaging/config.example.toml](packaging/config.example.toml). Key sections:

| Section | Purpose |
|---|---|
| `interface` / `web_bind` | NIC for XDP attachment and Web/API bind address |
| `whitelist` / `blacklist` | Static CIDR whitelist and permanent blacklist loaded at startup |
| `[rate_limit]` | Per-IP rate limiting and block duration |
| `[syn_proxy]` | IPv4 SYN Cookie proxy toggle |
| `[udp_flood]` / `[icmp_flood]` | Connectionless flood protection toggles |
| `[l7_scan]` | TCP first-packet fingerprint matching |
| `[adaptive]` | Repeat-offender escalation |
| `[geoip]` | Country/ASN based CIDR allow/block |
| `[threat_intel]` | Custom threat-intel feed synchronization |
| `[port_acl]` | Protocol/port level allow/drop rules |
| `[protection_projects]` | Control-plane policy grouping |

### Hot Reload

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

After starting the service, open `http://<host>:8720/`. The Dashboard shows real-time packet statistics, defense-module hits, top attackers, audit logs, and live control forms.

### Prometheus Metrics

```
http://<host>:8720/metrics
```

Key metrics include `eshield_dropped_total`, `eshield_passed_total`, `eshield_blacklist_blocked_total`, `eshield_rate_limited_total`, `eshield_geoip_blocked_total`, etc.

### JSON Stats Endpoint

```bash
curl -H "Authorization: Bearer <token>" http://<host>:8720/api/stats | jq
```

### TUI Dashboard

```bash
eshield tui
```

### Audit Log

- `GET /api/audit` queries audit events, supporting `limit`, `ip`, `action`, `from`, and `to` filters.
- `GET /api/audit/stream` pushes audit events in real time via SSE.

---

## API & Documentation

The complete REST API endpoints, request/response examples, and authentication details are in [docs/api.md](docs/api.md).

Other documentation:

| Document | Contents |
|---|---|
| [docs/architecture.md](docs/architecture.md) | System architecture, packet journey, BPF maps |
| [docs/deployment.md](docs/deployment.md) | Binary, systemd, container, and K8s deployment |
| [docs/operations.md](docs/operations.md) | Day-to-day commands, logs, alerting, backup/restore, troubleshooting |
| [docs/dev-linux.md](docs/dev-linux.md) | Dependencies, build, local testing |
| [docs/benchmark.md](docs/benchmark.md) | Test methodology and sample reports |

---

## Testing

### Unit Tests

```bash
cargo test --workspace --exclude eshield-ebpf
```

### Integration Tests

Requires root. Creates a veth pair in a network namespace and runs multiple scenarios:

```bash
sudo bash ./tests/netns_test.sh
sudo bash ./tests/full_attack_test.sh
```

Covers: blacklist, TCP RST on drop, rate limiting, SYN flood, UDP flood, ICMP flood, L7 fingerprint, service-stop restoration, SIGHUP reload, adaptive threshold, GeoIP/ASN, and threat intel.

### Benchmarks

```bash
cargo build --package eshield --target x86_64-unknown-linux-musl --release
sudo bash scripts/benchmark.sh
```

See [docs/benchmark.md](docs/benchmark.md) for details.

---

## Project Structure

```text
.
├── eshield/            # Userspace control plane
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

- **Host-level network scrubbing shield**: Targets SYN/UDP/ICMP Flood and CC attacks that exhaust connections or packet processing rather than raw bandwidth.
- **Not a DDoS silver bullet**: Terabit-scale bandwidth floods require upstream cloud mitigation; eShield cannot exceed physical network limits.
- **SYN Cookie proxy**: Currently IPv4 TCP only; all SYNs are challenged when enabled.
- **L7 scan**: Inspect only the first TCP packet; TCP reassembly is not supported.
- **Windows**: Cannot build or run directly; use a Linux environment.
- **Protection projects**: Currently a control-plane policy grouping; per-packet enforcement in eBPF is not yet enabled.

---

## License

Apache-2.0
