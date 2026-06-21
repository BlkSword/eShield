#!/bin/bash
# eShield 一键安装脚本
# 用法:
#   sudo bash scripts/install.sh           # 从 GitHub Release 下载二进制
#   sudo bash scripts/install.sh --build   # 从当前源码构建并安装
set -e

REPO="eshield/eshield"
VERSION="${VERSION:-0.1.0}"
INSTALL_BIN="/usr/local/bin/eshield"
INSTALL_CFG="/etc/eshield/config.toml"

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
if [ ! -f "$INSTALL_CFG" ]; then
    cat > "$INSTALL_CFG" <<'EOF'
interface = "eth0"
log_level = "info"
whitelist = ["127.0.0.1/32"]
blacklist = []
web_port = 8443

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
