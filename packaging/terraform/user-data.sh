#!/bin/bash
set -euo pipefail

VERSION="0.1.2"
DOWNLOAD_URL="https://github.com/eshield/eshield/releases/download/v${VERSION}/eshield-x86_64-unknown-linux-musl"

curl -sSL "$DOWNLOAD_URL" -o /usr/local/bin/eshield
chmod +x /usr/local/bin/eshield

mkdir -p /etc/eshield /var/lib/eshield /var/log/eshield
cat >/etc/eshield/config.toml <<'EOF'
interface = "eth0"
log_level = "info"
ebpf_log_enabled = false
web_port = 8443
whitelist = ["127.0.0.1/32", "::1/128"]
blacklist = []

[rate_limit]
enabled = true
threshold = 200
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 300

[syn_proxy]
enabled = false

[l7_scan]
enabled = false
patterns = []

[adaptive]
enabled = true
threshold = 10
window_s = 5
block_duration_s = 300
EOF

cat >/lib/systemd/system/eshield.service <<'EOF'
[Unit]
Description=eShield
After=network-online.target

[Service]
Type=simple
ExecStart=/usr/local/bin/eshield start --config /etc/eshield/config.toml
ExecReload=/bin/kill -HUP $MAINPID
Restart=on-failure
AmbientCapabilities=CAP_BPF CAP_NET_ADMIN CAP_NET_RAW CAP_PERFMON CAP_IPC_LOCK
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable eshield
systemctl start eshield
