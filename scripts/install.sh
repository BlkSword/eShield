#!/bin/bash
# eShield 一键安装脚本
# 用法:
#   sudo bash scripts/install.sh           # 从 GitHub Release 下载二进制
#   sudo bash scripts/install.sh --build   # 从当前源码构建并安装
set -e

REPO="eshield/eshield"
VERSION="${VERSION:-0.3.1}"
INSTALL_BIN="/usr/local/bin/eshield"
INSTALL_CFG="/etc/eshield/config.toml"
STORE_PATH="/var/lib/eshield/rules.redb"

ARCH=$(uname -m)
case "$ARCH" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *) echo "不支持的架构: $ARCH"; exit 1 ;;
esac

KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -lt 5 ] || \
   ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 10 ]); then
    echo "错误: 内核版本需要 5.10+，当前为 $(uname -r)"
    exit 1
fi

if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo "警告: 未检测到 BTF 支持，CO-RE 可能无法工作"
fi

build_local() {
    echo "正在从源码构建 eShield..."
    if ! command -v rustup >/dev/null 2>&1; then
        echo "错误: 未检测到 rustup，请先安装 Rust"
        exit 1
    fi
    rustup toolchain install nightly >/dev/null 2>&1 || true
    rustup target add bpfel-unknown-none --toolchain nightly >/dev/null 2>&1 || true
    rustup component add rust-src --toolchain nightly >/dev/null 2>&1 || true
    cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release
    cargo build --package eshield --target "$TARGET" --release
    cp "target/$TARGET/release/eshield" "$INSTALL_BIN"
}

download_release() {
    URL="https://github.com/${REPO}/releases/download/v${VERSION}/eshield-${TARGET}"
    echo "下载 eShield v${VERSION} (${TARGET})..."
    curl -sSL "$URL" -o "$INSTALL_BIN"
    chmod +x "$INSTALL_BIN"
}

if [ "${1:-}" = "--build" ]; then
    build_local
else
    download_release
fi

mkdir -p /etc/eshield
mkdir -p "$(dirname "$STORE_PATH")"

if [ ! -f "$INSTALL_CFG" ]; then
    cat > "$INSTALL_CFG" <<'EOF'
# 要挂载 XDP 的网卡
interface = "eth0"

log_level = "info"
log_json = false
ebpf_log_enabled = false

udp_flood_enabled = false
icmp_flood_enabled = false
tcp_reset_on_drop = false

web_bind = "0.0.0.0:8443"
# api_token = "changeme"

store_path = "/var/lib/eshield/rules.redb"

# 告警 Webhook（可选）
# alert_webhook_url = "https://hooks.example.com/eshield"
alert_webhook_type = "generic"
alert_threshold_dps = 1000
alert_cooldown_s = 60

whitelist = ["127.0.0.1/32"]
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

[geoip]
enabled = false
country_blocks_csv = "/etc/eshield/geoip_country.csv"
block_countries = ["XX"]
default_action = "pass"

[threat_intel]
enabled = false
EOF
    echo "已创建默认配置文件: $INSTALL_CFG"
fi

SERVICE_FILE="/etc/systemd/system/eshield.service"
if [ -f "systemd/eshield.service" ]; then
    cp "systemd/eshield.service" "$SERVICE_FILE"
else
    curl -sSL "https://raw.githubusercontent.com/${REPO}/v${VERSION}/systemd/eshield.service" -o "$SERVICE_FILE"
fi
chmod 644 "$SERVICE_FILE"

systemctl daemon-reload
systemctl enable eshield

# 如果已经在运行则热加载配置，否则启动
if systemctl is-active --quiet eshield; then
    systemctl reload eshield
else
    systemctl start eshield
fi

echo "✓ eShield 安装完成"
echo "  状态: sudo systemctl status eshield"
echo "  日志: sudo journalctl -u eshield -f"
echo "  重载: sudo systemctl reload eshield  # 发送 SIGHUP 热加载配置"
