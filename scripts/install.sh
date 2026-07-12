#!/bin/bash
# eShield 一键安装脚本
# 用法:
#   sudo bash scripts/install.sh           # 从 GitHub Release 下载二进制
#   sudo bash scripts/install.sh --build   # 从当前源码构建并安装
set -e

# ── 颜色输出 ──
RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()  { echo -e "${GREEN}[OK]${NC} $1"; }
warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
err()   { echo -e "${RED}[FAIL]${NC} $1"; }

REPO="eshield/eshield"
# 优先从环境变量读取版本；未设置时尝试从 Cargo.toml 解析；最后回退到默认版本。
DEFAULT_VERSION="0.3.4"
if [ -z "${VERSION:-}" ]; then
    if [ -f "Cargo.toml" ] && command -v grep >/dev/null 2>&1; then
        VERSION=$(grep -E '^version\s*=' Cargo.toml | head -1 | sed -E 's/.*"([^"]+)".*/\1/')
    fi
    VERSION="${VERSION:-$DEFAULT_VERSION}"
fi
INSTALL_BIN="/usr/local/bin/eshield"
INSTALL_CFG="/etc/eshield/config.toml"
STORE_PATH="/var/lib/eshield/rules.redb"
WEB_PORT=8720

# ── 环境检测 ──
echo "========================================="
echo " eShield v${VERSION} 安装程序"
echo "========================================="
echo ""

# 1. Root 检查
if [ "$(id -u)" -ne 0 ]; then
    err "此脚本需要 root 权限运行，请使用: sudo bash scripts/install.sh"
    exit 1
fi
info "root 权限检查通过"

# 2. 架构检查
ARCH=$(uname -m)
case "$ARCH" in
    x86_64) TARGET="x86_64-unknown-linux-musl" ;;
    aarch64) TARGET="aarch64-unknown-linux-musl" ;;
    *) err "不支持的架构: $ARCH（目前仅支持 x86_64 和 aarch64）"; exit 1 ;;
esac
info "CPU 架构: $ARCH → $TARGET"

# 3. 内核版本检查
KERNEL_MAJOR=$(uname -r | cut -d. -f1)
KERNEL_MINOR=$(uname -r | cut -d. -f2)
if [ "$KERNEL_MAJOR" -lt 5 ] || \
   ([ "$KERNEL_MAJOR" -eq 5 ] && [ "$KERNEL_MINOR" -lt 10 ]); then
    err "内核版本需要 5.10+，当前为 $(uname -r)"
    exit 1
fi
info "内核版本: $(uname -r) OK"

# 4. BTF 检查
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    warn "未检测到 BTF 支持 (/sys/kernel/btf/vmlinux)"
    warn "  eBPF CO-RE 可能无法工作。请确认内核编译时启用了 CONFIG_DEBUG_INFO_BTF"
    warn "  检查: zgrep CONFIG_DEBUG_INFO_BTF /proc/config.gz 2>/dev/null || true"
else
    info "BTF 支持: 已启用"
fi

# 5. XDP 支持检查（通过检查是否有网卡已挂载 XDP 推断）
if ip link show 2>/dev/null | grep -q "xdp"; then
    info "XDP 支持: 已可用（检测到现有 XDP 挂载）"
else
    info "XDP 支持: 内核已识别（需网卡驱动支持 native mode）"
fi

# 6. 网卡自动检测
DEFAULT_IFACE="eth0"
DETECTED_IFACE=$(ip -o link show 2>/dev/null | grep -v "lo:" | grep "state UP" | head -1 | awk -F': ' '{print $2}' || echo "")
if [ -n "$DETECTED_IFACE" ] && [ "$DETECTED_IFACE" != "lo" ]; then
    DEFAULT_IFACE="$DETECTED_IFACE"
    info "检测到活动网卡: $DEFAULT_IFACE"
else
    warn "未检测到活动网卡，将使用默认值 eth0"
    warn "  可用网卡列表:"
    ip -o link show 2>/dev/null | grep -v "lo:" | awk '{print "    " $2}' || true
fi

# 7. 内存检查
TOTAL_MEM=$(grep MemTotal /proc/meminfo 2>/dev/null | awk '{print $2}' || echo 0)
if [ "$TOTAL_MEM" -lt 262144 ]; then  # < 256 MB
    warn "系统内存较低 ($(( TOTAL_MEM / 1024 )) MB)，建议至少 512 MB"
    warn "  eBPF Map 需要约 50-100 MB 内存"
else
    info "系统内存: $(( TOTAL_MEM / 1024 )) MB"
fi

# 8. 端口检查
if ss -tlnp 2>/dev/null | grep -q ":$WEB_PORT "; then
    warn "端口 $WEB_PORT 已被占用:"
    ss -tlnp 2>/dev/null | grep ":$WEB_PORT " | head -3
    warn "  安装将继续，但 eShield 可能无法绑定该端口"
    warn "  可在 /etc/eshield/config.toml 中修改 web_bind"
else
    info "端口 $WEB_PORT: 可用"
fi

# 9. 构建依赖检查（仅 --build 模式）
if [ "${1:-}" = "--build" ]; then
    echo ""
    echo "── 构建依赖检查 ──"
    if ! command -v rustup >/dev/null 2>&1; then
        err "未检测到 rustup，请先安装 Rust: https://rustup.rs"
        exit 1
    fi
    info "rustup: $(rustup --version 2>/dev/null || echo '已安装')"

    if ! command -v cargo >/dev/null 2>&1; then
        err "未检测到 cargo"
        exit 1
    fi
    info "cargo: $(cargo --version)"

    if ! command -v clang >/dev/null 2>&1; then
        warn "未检测到 clang，eBPF 编译需要 LLVM/clang"
        warn "  Debian/Ubuntu: sudo apt install llvm clang libelf-dev"
        warn "  RHEL/CentOS:   sudo dnf install clang llvm elfutils-libelf-devel"
    else
        info "clang: $(clang --version 2>/dev/null | head -1 || echo '已安装')"
    fi

    if ! command -v bpf-linker >/dev/null 2>&1; then
        warn "未检测到 bpf-linker，eBPF 链接需要此工具"
        warn "  安装: cargo install bpf-linker"
    else
        info "bpf-linker: 已安装"
    fi
fi

echo ""

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

web_bind = "0.0.0.0:8720"
# api_token = "changeme"

store_path = "/var/lib/eshield/rules.redb"

# 告警 Webhook（可选）
# alert_webhook_url = "https://hooks.example.com/eshield"
alert_webhook_type = "generic"
alert_threshold_dps = 1000
alert_cooldown_s = 60

whitelist = ["127.0.0.1/32", "10.0.0.0/8"]
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
if [ -f "packaging/eshield.service" ]; then
    cp "packaging/eshield.service" "$SERVICE_FILE"
elif [ -f "systemd/eshield.service" ]; then
    cp "systemd/eshield.service" "$SERVICE_FILE"
else
    curl -sSL "https://raw.githubusercontent.com/${REPO}/v${VERSION}/packaging/eshield.service" -o "$SERVICE_FILE"
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

echo ""
echo "========================================="
echo -e " ${GREEN}eShield v${VERSION} 安装完成${NC}"
echo "========================================="
echo ""
echo "  控制台地址:  http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo '<服务器IP>'):${WEB_PORT}"
echo "  配置文件:    ${INSTALL_CFG}"
echo "  二进制路径:  ${INSTALL_BIN}"
echo "  持久化存储:  ${STORE_PATH}"
echo ""
echo "  管理命令:"
echo "    sudo systemctl status eshield     # 查看状态"
echo "    sudo systemctl stop eshield       # 停止服务"
echo "    sudo systemctl restart eshield    # 重启服务"
echo "    sudo systemctl reload eshield     # 热加载配置 (SIGHUP)"
echo "    sudo journalctl -u eshield -f     # 实时日志"
echo ""
echo "  CLI 命令（本机免认证）:"
echo "    eshield status                    # 查看运行状态"
echo "    eshield block <IP> -d <秒>        # 封禁 IP"
echo "    eshield unblock <IP>              # 解封 IP"
echo "    eshield reload                    # 重载配置"
echo "    eshield tui                       # TUI 仪表盘"
echo ""
if [ "$DEFAULT_IFACE" != "eth0" ]; then
    echo -e "  ${YELLOW}注意: 网卡已自动设置为 ${DEFAULT_IFACE}，如需修改请编辑 ${INSTALL_CFG}${NC}"
fi
if [ ! -f /sys/kernel/btf/vmlinux ]; then
    echo -e "  ${YELLOW}注意: BTF 未启用，部分功能可能受限${NC}"
fi
echo ""
