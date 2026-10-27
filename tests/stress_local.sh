#!/bin/bash
# eShield 本地压测：混合洪水 soak + 黑名单 map 饱和。
#
# 目的：验证「长时间混合洪水下不崩溃、计数单调、控制面仍可响应」以及
#      「BLACKLIST 接近容量上限时批量封禁/统计/查询仍然正确」。
#
# 注意：eShield 与 feed 服务都跑在 netns 内，所以所有 API 调用必须
#      `ip netns exec` 进去（宿主机访问不到 ns 内的 127.0.0.1）。
#
# 用法：
#   sudo SKIP_BUILD=1 bash tests/stress_local.sh
#   sudo DURATION=180 SATURATE=50000 bash tests/stress_local.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

DURATION="${DURATION:-60}"
SATURATE="${SATURATE:-10000}"
PORT="${PORT:-18721}"

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

NS_S="st-server"; NS_C="st-client"
BIN=/tmp/eshield-stress; CFG=/tmp/eshield-stress.toml; STORE=/tmp/eshield-stress.redb
LOG=/tmp/eshield-stress.log; FEED_DIR=/tmp/eshield-stress-feed; API="http://127.0.0.1:${PORT}"
FAILS=0

check() {
    if [ "$2" = "1" ]; then echo "[PASS] $1 ${3}"; else echo "[FAIL] $1 ${3}"; FAILS=$((FAILS+1)); fi
}
# 所有 API 调用都要在 netns 内执行
ns_curl() { ip netns exec "$NS_S" curl -sS --max-time 5 "$@"; }
stat() { ns_curl "$API/api/stats" | jq -r ".$1 // 0"; }

cleanup() {
    kill "$ESHIELD_PID" "$FEED_PID" 2>/dev/null || true
    wait "$ESHIELD_PID" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    rm -rf "$BIN" "$CFG" "$STORE" "$LOG" "$FEED_DIR"
}
trap cleanup EXIT

pkill -9 -f '^/tmp/eshield-stress( |$)' 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip netns del "$NS_S" 2>/dev/null || true
mkdir -p "$FEED_DIR"
cp target/x86_64-unknown-linux-musl/release/eshield "$BIN" && chmod +x "$BIN"

ip netns add "$NS_S"; ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"; ip link set veth-c netns "$NS_C"
ip -n "$NS_S" addr add 10.11.0.1/24 dev veth-s
ip -n "$NS_C" addr add 10.11.0.2/24 dev veth-c
ip -n "$NS_S" link set veth-s up; ip -n "$NS_C" link set veth-c up
ip -n "$NS_S" link set lo up; ip -n "$NS_C" link set lo up

cat > "$CFG" <<TOML
interface = "veth-s"
web_bind = "127.0.0.1:${PORT}"
log_level = "warn"
store_path = "$STORE"
whitelist = ["127.0.0.1/32"]
blacklist = []
udp_flood_enabled = true
icmp_flood_enabled = true

[rate_limit]
enabled = true
threshold = 2000
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 30

[adaptive]
enabled = false

[threat_intel]
enabled = true
[[threat_intel.feeds]]
name = "saturate"
url = "http://127.0.0.1:18099/feed.txt"
interval_s = 86400
action = "drop"
confidence = 90
TOML

# 黑名单饱和用 feed：一次性批量封禁 SATURATE 条（服务跑在 netns 内）
python3 - "$FEED_DIR/feed.txt" "$SATURATE" <<'PY'
import sys
path, n = sys.argv[1], int(sys.argv[2])
with open(path, "w") as f:
    for i in range(n):
        f.write(f"172.30.{(i // 256) % 256}.{i % 256}\n")
PY
ip netns exec "$NS_S" sh -c "cd '$FEED_DIR' && python3 -m http.server 18099 --bind 127.0.0.1" >/dev/null 2>&1 &
FEED_PID=$!
rm -f "$STORE"
ip netns exec "$NS_S" env ESHIELD_XDP_MODE=skb "$BIN" start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
READY=0
for _ in $(seq 1 40); do
    if ns_curl -sf "$API/ready" >/dev/null 2>&1; then READY=1; break; fi
    sleep 0.25
done
if [ "$READY" != "1" ]; then
    echo "FAIL: API not ready"; tail -20 "$LOG"; exit 1
fi

echo "=== Phase A: ${DURATION}s 混合洪水 soak（SYN + UDP 双路） ==="
B_PKT=$(stat total_packets); B_DROP=$(stat total_dropped)
P1=$(ns_curl "$API/metrics" | grep -c '^eshield_' || true)
for i in $(seq 1 $((DURATION / 10 + 1))); do
    timeout 10s ip netns exec "$NS_C" hping3 --flood -S -p 80 10.11.0.1 >/dev/null 2>&1 &
    timeout 10s ip netns exec "$NS_C" hping3 --flood --udp -p 53 10.11.0.1 >/dev/null 2>&1 &
    sleep 10
    echo "  t=$((i*10))s dropped=$(stat total_dropped) pps=$(stat current_pps) dps=$(stat current_dps)"
    ns_curl -sf "$API/api/stats" >/dev/null || { echo "FAIL: 控制面在压测中失联"; FAILS=$((FAILS+1)); break; }
done
sleep 2
A_PKT=$(stat total_packets); A_DROP=$(stat total_dropped)
P2=$(ns_curl "$API/metrics" | grep -c '^eshield_' || true)
echo "  soak 合计处理 $((A_PKT - B_PKT)) 包，丢弃 $((A_DROP - B_DROP)) 包"
check "压测期间控制面持续可用" "1" ""
check "总包数单调增长" "$([ "$A_PKT" -gt "$B_PKT" ] && echo 1 || echo 0)" "+$((A_PKT-B_PKT))"
check "指标族数量稳定（$P1 → $P2）" "$([ "$P2" -ge "$P1" ] && echo 1 || echo 0)" ""
check "进程未崩溃" "$(pgrep -f '^/tmp/eshield-stress' >/dev/null && echo 1 || echo 0)" ""

echo
echo "=== Phase B: 黑名单饱和（通过威胁情报一次性写入 ${SATURATE} 条） ==="
ns_curl -m 10 -X POST "$API/threat-intel/sync" >/dev/null
CNT=0
for _ in $(seq 1 60); do
    CNT=$(ns_curl "$API/api/blacklist" | jq -r '.count // 0')
    [ "$CNT" -gt 0 ] && break
    sleep 1
done
echo "  黑名单条目: $CNT"
check "批量封禁写入黑名单" "$([ "$CNT" -gt 0 ] && echo 1 || echo 0)" "count=$CNT"
# /metrics 的 map 条目数是后台按 metrics_interval_s（默认 30s）采样，需要轮询等待
MET=""
for _ in $(seq 1 25); do
    MET=$(ns_curl "$API/metrics" | grep 'eshield_map_entries{.*BLACKLIST' || true)
    echo "$MET" | grep -qE ' [1-9][0-9]*$' && break
    sleep 2
done
echo "  $MET"
check "BLACKLIST 条目数指标已采样" "$(echo "$MET" | grep -qE ' [1-9][0-9]*$' && echo 1 || echo 0)" ""
R=$(ns_curl -o /dev/null -w '%{http_code}' --max-time 3 "$API/healthz" || true)
check "饱和状态下 API 仍健康" "$([ "$R" = "200" ] && echo 1 || echo 0)" "healthz=$R"

echo
if [ "$FAILS" -ne 0 ]; then
    echo "=== 压测失败：$FAILS 项未通过 ==="
    exit 1
fi
echo "=== 压测完成：全部检查通过 ==="
