# Changelog

All notable changes to this project will be documented in this file.

## [0.3.1] - Unreleased

### Added
- Modern brand-style JS Challenge page (`challenge.html`) with automatic IP display.
- `tcp_reset_on_drop` runtime option and eBPF TCP RST reply for dropped TCP traffic.
- Dashboard settings page now shows runtime status, alert webhook, and Challenge config.
- Dashboard network protection page upgraded to grouped toggle switches with descriptions.
- Runtime snapshot extended with interface, web bind, logging, alert, adaptive, and challenge metadata.

### Changed
- Dashboard switches replaced with a unified modern toggle component.
- `AdaptiveConfig` now derives `Serialize` for runtime snapshot exposure.

### Fixed
- Test 1.5 (`tcp_reset_on_drop`) now works in veth netns by attaching a dummy XDP pass-through on the peer interface.
- TCP RST checksum folding corrected to fold high 16 bits before ones-complement.

## [0.3.0] - 2026-06-27

### Added
- In-memory time-series metrics window sampled every 10 seconds.
- New API `GET /api/metrics/series?duration_s=` for traffic trend data.
- Extended `/api/stats` with `total_packets`, `total_passed`, `current_pps`, `current_dps`.
- Modern Web Dashboard v3:
  - Sidebar navigation with hash routing.
  - Dark / light theme toggle.
  - Card-based metrics and ECharts traffic trend chart.
  - IP intelligence drawer for TOP attackers.
  - Toast notifications and responsive layout.
- WAF rule editor in Dashboard: add, edit, delete, reorder rules.
- Port / Protocol ACL editor in Dashboard with persistence.
- L7 fingerprint editor in Dashboard with persistence.
- RuleStore persistence extended to WAF rules, Port ACL, and L7 patterns.
- REST APIs: `/api/waf/rules`, `/api/port-acl`, `/api/l7-patterns`.

### Changed
- `RuntimeConfigSnapshot` now includes `port_acl` and `l7_scan` for the Dashboard.
- ROADMAP.md updated to reflect v0.2.0 completion and v0.3.0 plan.

### Fixed
- Cleaned up all compiler warnings in both eBPF and userspace code.

## [0.2.0] - 2026-06-27

### Added
- Stateful SYN Proxy with SYN Cookie and TCP MSS option negotiation.
- HTTP WAF rule engine (method / path_prefix / host / user_agent / body_prefix matching).
- JS/302 Challenge mode with temporary allowlist.
- GeoIP / ASN CIDR filtering (custom CSV and MaxMind MMDB).
- Threat intelligence feed sync (text / CSV / JSON, AbuseIPDB / CINS / custom URLs).
- Extended Web API and Dashboard for WAF, GeoIP, threat intel, and challenge.
- Integration tests for WAF, Challenge, GeoIP, and threat intel.

### Changed
- Rule persistence migrated from SQLite to redb.
- Persisted store skips historical `BLACKLIST` entries on load to avoid stale dynamic blocks overriding config changes.

## [0.1.2] - Earlier

### Added
- IPv6 full path support.
- Port / protocol ACL.
- UDP / ICMP flood detection.
- API authentication, audit logging, and rule persistence.
- Web Dashboard v2, TUI dashboard, Prometheus metrics.
- SIGHUP config reload and systemd packaging.
