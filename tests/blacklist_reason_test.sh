#!/bin/bash
# 黑名单原因链 + 限速计数维度（dport_grouping）回归测试。
#
# 覆盖 v0.4.8 新行为：
#   1) 自动模块封禁后，显式 API 再封：原因=手动封禁，last_reason=速率限制（不丢根因）
#   2) dport_grouping=true 时按 源IP+目的端口 计数：两个端口各 ~500pps 不封禁
#   3) dport_grouping=false 时按 IP 合计计数：单端口 ~1000pps 触发封禁
#
# 用法：sudo SKIP_BUILD=1 bash tests/blacklist_reason_test.sh
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
    "$CARGO" +"$EBPF_TOOLCHAIN" build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
fi

NS_S="br-server"; NS_C="br-client"
BIN=/tmp/eshield-br; CFG=/tmp/eshield-br.toml; STORE=/tmp/eshield-br.redb; LOG=/tmp/eshield-br.log
PORT=18722; API="http://127.0.0.1:${PORT}"; CLIENT_IP=10.12.0.2; SERVER_IP=10.12.0.1
FAILS=0

check() { if [ "$2" = "1" ]; then echo "[PASS] $3"; else echo "[FAIL] $3"; FAILS=$((FAILS+1)); fi; }
nsapi() { ip netns exec "$NS_S" curl -sS --max-time 5 "$@"; }
bl_entry() { nsapi "$API/api/blacklist" | jq -r --arg ip "$CLIENT_IP" '.entries[] | select(.ip == $ip) | "\(.reason)|\(.last_reason // "")"' | head -1; }
unblock() { nsapi -o /dev/null -X DELETE -H 'Content-Type: application/json' -d "{\"ip\":\"$CLIENT_IP\"}" "$API/api/blacklist" || true; sleep 1; }
set_rl() { nsapi -o /dev/null -X PATCH -H 'Content-Type: application/json' -d "$1" "$API/api/config"; }

cleanup() {
    kill "$ESHIELD_PID" 2>/dev/null || true
    wait "$ESHIELD_PID" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    rm -f "$BIN" "$CFG" "$STORE" "$LOG"
}
trap cleanup EXIT

pkill -9 -f '^/tmp/eshield-br( |$)' 2>/dev/null || true
ip netns del "$NS_C" 2>/dev/null || true
ip netns del "$NS_S" 2>/dev/null || true
cp target/x86_64-unknown-linux-musl/release/eshield "$BIN" && chmod +x "$BIN"

ip netns add "$NS_S"; ip netns add "$NS_C"
ip link add veth-s type veth peer name veth-c
ip link set veth-s netns "$NS_S"; ip link set veth-c netns "$NS_C"
ip -n "$NS_S" addr add "$SERVER_IP/24" dev veth-s
ip -n "$NS_C" addr add "$CLIENT_IP/24" dev veth-c
ip -n "$NS_S" link set veth-s up; ip -n "$NS_C" link set veth-c up
ip -n "$NS_S" link set lo up; ip -n "$NS_C" link set lo up

cat > "$CFG" <<TOML
interface = "veth-s"
web_bind = "127.0.0.1:${PORT}"
log_level = "warn"
store_path = "$STORE"
whitelist = ["127.0.0.1/32"]
blacklist = []
udp_flood_enabled = false
icmp_flood_enabled = false

[rate_limit]
enabled = true
threshold = 8
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 60
dport_grouping = false

[adaptive]
enabled = false
TOML
rm -f "$STORE"

ip netns exec "$NS_S" env ESHIELD_XDP_MODE=skb "$BIN" start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
for _ in $(seq 1 40); do nsapi -sf "$API/ready" >/dev/null 2>&1 && break; sleep 0.25; done
nsapi -sf "$API/api/stats" >/dev/null || { echo "FAIL: API not ready"; tail -20 "$LOG"; exit 1; }

echo "=== 1) 自动封禁：速率限制 ==="
unblock
timeout 2s ip netns exec "$NS_C" hping3 --flood --ack -p 80 "$SERVER_IP" >/dev/null 2>&1 || true
sleep 3
ENT=$(bl_entry)
check "1" "$([ "${ENT%%|*}" = "速率限制" ] && echo 1 || echo 0)" "自动封禁原因=速率限制 (实际: $ENT)"

echo "=== 2) 显式 API 再封：保留根因 ==="
nsapi -o /dev/null -X POST -H 'Content-Type: application/json' \
    -d "{\"ip\":\"$CLIENT_IP\",\"duration_s\":60}" "$API/api/blacklist"
sleep 1
ENT=$(bl_entry)
REASON="${ENT%%|*}"; LAST="${ENT##*|}"
check "2" "$([ "$REASON" = "手动封禁" ] && [ "$LAST" = "速率限制" ] && echo 1 || echo 0)" \
      "原因=手动封禁 叠加=速率限制 (实际: $ENT)"

# 阈值口径：指数衰减计数器稳态 ≈ 每 tick 到达数 / (1 - decay)。
# 这里 100ms tick、7/8 decay，500pps ≈ 50/100ms → 稳态 ≈ 400，所以阈值取 600：
#   分组开启：每端口 400 < 600 → 不封禁；关闭：合计 800 > 600 → 封禁。
echo "=== 3) dport_grouping=true：两端口各 ~500pps 不应封禁 ==="
unblock
set_rl '{"rate_limit":{"enabled":true,"threshold":600,"tick_ms":100,"decay_num":7,"decay_den":8,"block_duration_s":60,"dport_grouping":true}}'
sleep 1
echo "  [3.1] 启动两路 500pps（端口 8001/8002）"
timeout 3s ip netns exec "$NS_C" hping3 --ack -p 8001 -i u2000 "$SERVER_IP" >/dev/null 2>&1 &
H1=$!
timeout 3s ip netns exec "$NS_C" hping3 --ack -p 8002 -i u2000 "$SERVER_IP" >/dev/null 2>&1 &
H2=$!
sleep 4
kill "$H1" "$H2" 2>/dev/null || true
wait "$H1" 2>/dev/null || true
wait "$H2" 2>/dev/null || true
echo "  [3.2] 洪泛结束，等待统计同步"
sleep 2
ENT=$(bl_entry)
check "3" "$([ -z "$ENT" ] && echo 1 || echo 0)" "按端口分组时不误封 (实际: ${ENT:-<未封禁>})"

echo "=== 4) dport_grouping=false：单端口 ~1000pps 应封禁 ==="
unblock
set_rl '{"rate_limit":{"enabled":true,"threshold":600,"tick_ms":100,"decay_num":7,"decay_den":8,"block_duration_s":60,"dport_grouping":false}}'
sleep 1
echo "  [4.1] 单端口 1000pps（端口 8003）"
timeout 2s ip netns exec "$NS_C" hping3 --ack -p 8003 -i u1000 "$SERVER_IP" >/dev/null 2>&1 || true
echo "  [4.2] 洪泛结束，等待统计同步"
sleep 3
ENT=$(bl_entry)
check "4" "$([ -n "$ENT" ] && [ "${ENT%%|*}" = "速率限制" ] && echo 1 || echo 0)" "按 IP 合计计数时封禁 (实际: ${ENT:-<未封禁>})"

echo
if [ "$FAILS" -ne 0 ]; then
    echo "=== 失败：$FAILS 项未通过 ==="
    exit 1
fi
echo "=== 黑名单原因链 / 计数维度测试全部通过 ==="
