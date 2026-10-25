#!/bin/bash
# 验证 SYN Proxy 的「挑战态兜底」修复：
# 带 TCP timestamp 选项（32 字节 TCP 头）的 SYN 无法构造 Cookie 挑战包，
# 一旦源超过 SYN Flood 阈值必须被 DROP，而不是直通内核。
#
# 背景：修复前 handle_syn 对这类包头返回 NO_ACTION，主流程放行，且该包的
# rate_counted 已置位导致全局限速也被跳过 —— SYN Proxy 开启后这类 Flood 无防护。
#
# 需要 root + Linux（netns/veth）+ hping3。用法：
#   sudo SKIP_BUILD=1 bash tests/syn_proxy_options_test.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

if [ -z "${CARGO:-}" ]; then
    if command -v cargo >/dev/null 2>&1; then
        CARGO="$(command -v cargo)"
    elif [ -x "$HOME/.cargo/bin/cargo" ]; then
        CARGO="$HOME/.cargo/bin/cargo"
    elif [ -x /root/.cargo/bin/cargo ]; then
        CARGO=/root/.cargo/bin/cargo
    else
        echo "FAIL: cargo not found (set CARGO=/path/to/cargo)"
        exit 1
    fi
fi
EBPF_TOOLCHAIN="${ESHIELD_EBPF_TOOLCHAIN:-nightly-2026-07-31}"
export PATH="$(dirname "$CARGO"):$PATH"

cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    echo "=== Building eShield ==="
    "$CARGO" +"$EBPF_TOOLCHAIN" build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
fi

NS_SERVER="sc-server"
NS_CLIENT="sc-client"
BIN=/tmp/eshield-sc
CFG=/tmp/eshield-sc.toml
LOG=/tmp/eshield-sc.log
STORE=/tmp/eshield-sc.redb
WEB="127.0.0.1:18720"

cleanup() {
    kill "$ESHIELD_PID" 2>/dev/null || true
    wait "$ESHIELD_PID" 2>/dev/null || true
    ip netns del "$NS_CLIENT" 2>/dev/null || true
    ip netns del "$NS_SERVER" 2>/dev/null || true
    rm -f "$BIN" "$CFG" "$LOG" "$STORE" /tmp/sc-before.json /tmp/sc-after.json
}
trap cleanup EXIT

pkill -9 -f '^/tmp/eshield-sc( |$)' 2>/dev/null || true
ip netns del "$NS_CLIENT" 2>/dev/null || true
ip netns del "$NS_SERVER" 2>/dev/null || true

cp target/x86_64-unknown-linux-musl/release/eshield "$BIN"
chmod +x "$BIN"

ip netns add "$NS_SERVER"
ip netns add "$NS_CLIENT"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_SERVER"
ip link set veth-c netns "$NS_CLIENT"
ip -n "$NS_SERVER" addr add 10.9.0.1/24 dev veth-s
ip -n "$NS_CLIENT" addr add 10.9.0.2/24 dev veth-c
ip -n "$NS_SERVER" link set veth-s up
ip -n "$NS_CLIENT" link set veth-c up
ip -n "$NS_SERVER" link set lo up
ip -n "$NS_CLIENT" link set lo up

cat > "$CFG" <<TOML
interface = "veth-s"
log_level = "info"
web_bind = "$WEB"
store_path = "$STORE"
whitelist = []
blacklist = []

[rate_limit]
enabled = false
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8

[syn_proxy]
enabled = true
TOML
rm -f "$STORE"

ip netns exec "$NS_SERVER" env ESHIELD_XDP_MODE=skb "$BIN" start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

if ! ip netns exec "$NS_SERVER" curl -sf --max-time 3 "http://${WEB}/api/stats" > /tmp/sc-before.json; then
    echo "FAIL: eShield API not reachable; log:"
    tail -20 "$LOG"
    exit 1
fi

# 30 个带 TCP timestamp 选项的 SYN（32 字节 TCP 头）：阈值 5，超出部分应被兜底丢弃
ip netns exec "$NS_CLIENT" hping3 -S --tcp-timestamp -p 80 -c 30 -i u20000 10.9.0.1 >/dev/null 2>&1 || true
sleep 3

ip netns exec "$NS_SERVER" curl -sf --max-time 3 "http://${WEB}/api/stats" > /tmp/sc-after.json

python3 - <<'PY'
import json

before = json.load(open("/tmp/sc-before.json"))
after = json.load(open("/tmp/sc-after.json"))
d_pkt = after["total_packets"] - before["total_packets"]
d_pass = after["total_passed"] - before["total_passed"]
d_syn = after["syn_flood_blocked"] - before["syn_flood_blocked"]
print(f"delta: packets={d_pkt} passed={d_pass} syn_flood_blocked={d_syn}")

if d_syn < 1:
    raise SystemExit("FAIL: 带 TCP 选项的 SYN Flood 未触发 syn_flood_blocked（兜底未生效）")
if d_pass >= 30:
    raise SystemExit("FAIL: 所有 SYN 都被放行，SYN Proxy 未起作用")
print("PASS: 带 TCP 选项的 SYN Flood 在挑战态被兜底 DROP")
PY
