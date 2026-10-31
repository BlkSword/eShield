#!/bin/bash
# v0.5.0 新增能力回归（netns）：
#   1) [xdp].fragment_policy = drop       → 非首片分片被丢弃并计数
#   2) [xdp].fragment_policy = rate_limit → 分片按协议聚合限速，超阈值丢弃并计数
#   3) [xdp].fragment_policy = pass        → 放行，不产生 fragment_blocked
#   4) [rate_limit].block_mode = soft      → 超限只丢弃不写黑名单
#   5) [rate_limit].block_mode = hard      → 超限写入黑名单
#   6) port_rate_limit 覆盖 TCP            → 伪造源 SYN Flood 被端口维度限速拦截
#   7) /api/map-usage                      → map 条目/上限/使用率
#   8) /api/audit/verify                   → 审计哈希链校验（篡改后必须失败）
#
# 用法：sudo SKIP_BUILD=1 bash tests/v050_features_test.sh
set -u

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

if [ -z "${CARGO:-}" ]; then
    for c in "$(command -v cargo 2>/dev/null)" "$HOME/.cargo/bin/cargo" /root/.cargo/bin/cargo; do
        [ -x "$c" ] && CARGO="$c" && break
    done
fi
[ -n "${CARGO:-}" ] || { echo "FAIL: cargo not found"; exit 1; }
export PATH="$(dirname "$CARGO"):$PATH"
cd "$(dirname "$0")/.." || exit 1

if [ -z "${SKIP_BUILD:-}" ]; then
    "$CARGO" +"${ESHIELD_EBPF_TOOLCHAIN:-nightly-2026-07-31}" build --package eshield-ebpf \
        --target bpfel-unknown-none -Z build-std=core --release -q || exit 1
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q || exit 1
fi

NS_S=v5-server; NS_C=v5-client
PORT=18731; API="http://127.0.0.1:${PORT}"
AUDIT_LOG=/tmp/v050-audit.log
FRAG_SENDER=/tmp/v050_send_frags.py
FAILS=0
check() { if [ "$2" = "1" ]; then echo "[PASS] $3"; else echo "[FAIL] $3"; FAILS=$((FAILS+1)); fi; }
num() { echo "${1:-0}" | tr -dc '0-9' | head -c 18; }

cat > "$FRAG_SENDER" <<'PY'
#!/usr/bin/env python3
"""发送真正的非首片 IPv4 分片（frag_off != 0），用于验证 fragment_policy。"""
import socket
import struct
import sys

dst = sys.argv[1]
count = int(sys.argv[2]) if len(sys.argv) > 2 else 2000
proto = 17  # UDP

def csum(data: bytes) -> int:
    if len(data) % 2:
        data += b"\0"
    total = sum(struct.unpack("!%dH" % (len(data) // 2), data))
    while total >> 16:
        total = (total & 0xFFFF) + (total >> 16)
    return ~total & 0xFFFF

payload = b"X" * 64
# 非首片：frag_off = 185（1480 字节偏移），MF=1
sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
for i in range(count):
    ident = 0x4242
    src = socket.inet_aton("10.55.0.2")
    dstb = socket.inet_aton(dst)
    frag_off = 185 | 0x2000  # offset 185 * 8 = 1480, MF=1
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag_off, 64, proto, 0, src, dstb)
    hdr = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20 + len(payload), ident, frag_off, 64, proto, csum(hdr), src, dstb)
    try:
        sock.sendto(hdr + payload, (dst, 0))
    except OSError:
        break
print("sent", count)
PY

cleanup() {
    [ -n "${PID:-}" ] && kill "$PID" 2>/dev/null
    [ -n "${PID:-}" ] && wait "$PID" 2>/dev/null
    ip netns del "$NS_C" 2>/dev/null
    ip netns del "$NS_S" 2>/dev/null
    rm -f /tmp/eshield-v5 /tmp/v050-audit.log* /tmp/eshield-v050.redb "$FRAG_SENDER" 2>/dev/null
}
trap cleanup EXIT

mkns() {
    ip netns del "$NS_C" 2>/dev/null; ip netns del "$NS_S" 2>/dev/null
    ip netns add "$NS_S"; ip netns add "$NS_C"
    ip link add veth-v5 type veth peer name veth-v5c
    ip link set veth-v5 netns "$NS_S"; ip link set veth-v5c netns "$NS_C"
    ip -n "$NS_S" addr add 10.55.0.1/24 dev veth-v5
    ip -n "$NS_C" addr add 10.55.0.2/24 dev veth-v5c
    ip -n "$NS_S" link set veth-v5 up; ip -n "$NS_C" link set veth-v5c up
    ip -n "$NS_S" link set lo up; ip -n "$NS_C" link set lo up
}

# 基础配置：只有网络/存储/开关，模块段由各用例追加（避免重复 table）
write_cfg() {
    cat > /tmp/eshield-v5.toml <<'TOML'
interface = "veth-v5"
web_bind = "127.0.0.1:18731"
log_level = "warn"
store_path = "/tmp/eshield-v050.redb"
whitelist = ["127.0.0.1/32"]
blacklist = []
udp_flood_enabled = false
icmp_flood_enabled = false

[xdp]
mode = "auto"
disable_offloads = true
TOML
    if [ -n "${1:-}" ]; then
        printf '\n%s\n' "$1" >> /tmp/eshield-v5.toml
    fi
    rm -f /tmp/eshield-v050.redb
}

start_es() {
    pkill -9 -f '^/tmp/eshield-v5 start' 2>/dev/null
    sleep 0.2
    ip netns exec "$NS_S" /tmp/eshield-v5 start --config /tmp/eshield-v5.toml >/tmp/v5.log 2>&1 &
    PID=$!
    for _ in $(seq 1 60); do
        if ip netns exec "$NS_S" curl -sf --max-time 2 "$API/ready" >/dev/null 2>&1; then return 0; fi
        sleep 0.25
    done
    echo "eShield 启动失败："; tail -20 /tmp/v5.log
    return 1
}

api() { ip netns exec "$NS_S" curl -s --max-time 5 "$@"; }
stat_field() { api "$API/api/stats" | jq -r ".$1 // 0"; }
blacklist_count() { api "$API/api/blacklist" | jq -r '.count // 0'; }
send_frags() { ip netns exec "$NS_C" python3 "$FRAG_SENDER" 10.55.0.1 "${1:-3000}" >/dev/null 2>&1; }

pkill -9 -f '^/tmp/eshield-v5 start' 2>/dev/null
mkns
cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield-v5 && chmod +x /tmp/eshield-v5

echo "=== 1) fragment_policy = drop ==="
write_cfg ''
sed -i 's|^disable_offloads = true$|disable_offloads = true\nfragment_policy = "drop"|' /tmp/eshield-v5.toml
start_es || exit 1
send_frags 3000
sleep 1.6
FB=$(stat_field fragment_blocked)
check "1" "$([ "$(num "$FB")" -gt 0 ] && echo 1 || echo 0)" "drop 模式：fragment_blocked=$FB"

echo "=== 2) fragment_policy = rate_limit ==="
write_cfg '[port_rate_limit]
enabled = true
threshold = 5
tick_ms = 100'
sed -i 's|^disable_offloads = true$|disable_offloads = true\nfragment_policy = "rate_limit"|' /tmp/eshield-v5.toml
start_es || exit 1
send_frags 3000
sleep 1.6
FB=$(stat_field fragment_blocked)
check "2" "$([ "$(num "$FB")" -gt 0 ] && echo 1 || echo 0)" "rate_limit 模式：fragment_blocked=$FB"

echo "=== 3) fragment_policy = pass ==="
write_cfg ''
sed -i 's|^disable_offloads = true$|disable_offloads = true\nfragment_policy = "pass"|' /tmp/eshield-v5.toml
start_es || exit 1
send_frags 1500
sleep 1.6
FB=$(stat_field fragment_blocked)
check "3" "$([ "$(num "$FB")" -eq 0 ] && echo 1 || echo 0)" "pass 模式：fragment_blocked=$FB（应为 0）"

echo "=== 4) rate_limit block_mode = soft ==="
write_cfg '[rate_limit]
enabled = true
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 60
block_mode = "soft"'
start_es || exit 1
ip netns exec "$NS_C" timeout 4 hping3 --udp --flood -p 53 10.55.0.1 >/dev/null 2>&1
sleep 1.2
RL=$(stat_field rate_limited)
BL=$(blacklist_count)
check "4a" "$([ "$(num "$RL")" -gt 0 ] && echo 1 || echo 0)" "soft 模式：rate_limited=$RL（应有丢弃）"
check "4b" "$([ "$(num "$BL")" -eq 0 ] && echo 1 || echo 0)" "soft 模式：blacklist=$BL（不应拉黑）"

echo "=== 5) rate_limit block_mode = hard ==="
write_cfg '[rate_limit]
enabled = true
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 60
block_mode = "hard"'
start_es || exit 1
ip netns exec "$NS_C" timeout 4 hping3 --udp --flood -p 53 10.55.0.1 >/dev/null 2>&1
sleep 1.2
BL=$(blacklist_count)
check "5" "$([ "$(num "$BL")" -gt 0 ] && echo 1 || echo 0)" "hard 模式：blacklist=$BL（应 >= 1）"

echo "=== 6) port_rate_limit 覆盖 TCP（伪造源绕过场景）==="
write_cfg '[port_rate_limit]
enabled = true
threshold = 5
tick_ms = 100'
start_es || exit 1
ip netns exec "$NS_C" timeout 5 hping3 --rand-source -S --flood -p 80 10.55.0.1 >/dev/null 2>&1
sleep 0.5
PR=$(stat_field port_rate_blocked)
BL=$(blacklist_count)
check "6a" "$([ "$(num "$PR")" -gt 0 ] && echo 1 || echo 0)" "TCP 端口聚合限速：port_rate_blocked=$PR"
check "6b" "$([ "$(num "$BL")" -eq 0 ] && echo 1 || echo 0)" "伪造源未进入黑名单：blacklist=$BL"

echo "=== 7) /api/map-usage ==="
MU=$(api "$API/api/map-usage")
BL_JSON=$(echo "$MU" | jq -r '[.maps[] | select(.name=="BLACKLIST")][0] | "\(.entries)/\(.max)/\(.ratio)"')
check "7" "$(echo "$MU" | jq -e '(.maps | length) > 0 and (.maps[0].max > 0) and ((.maps[0].ratio | type) == "number")' >/dev/null 2>&1 && echo 1 || echo 0)" "map-usage 有效（BLACKLIST=${BL_JSON}）"

echo "=== 8) /api/audit/verify 审计哈希链 ==="
write_cfg '[audit]
enabled = true
path = "/tmp/v050-audit.log"'
rm -f "$AUDIT_LOG"
start_es || exit 1
api -X POST -H 'Content-Type: application/json' -d '{"ip":"10.55.9.9","duration_s":60}' "$API/api/blacklist" >/dev/null
sleep 0.5
V1=$(api "$API/api/audit/verify")
OK1=$(echo "$V1" | jq -r '.ok')
CHK=$(echo "$V1" | jq -r '.checked // 0')
check "8a" "$([ "$OK1" = "true" ] && [ "$(num "$CHK")" -gt 0 ] && echo 1 || echo 0)" "未篡改：ok=$OK1 checked=$CHK"

python3 - <<'PY'
import json
p = "/tmp/v050-audit.log"
lines = open(p).read().splitlines()
if lines:
    v = json.loads(lines[0])
    v["actor"] = "tampered"
    lines[0] = json.dumps(v)
open(p, "w").write("\n".join(lines) + "\n")
PY
V2=$(api "$API/api/audit/verify")
OK2=$(echo "$V2" | jq -r '.ok')
BAD=$(echo "$V2" | jq -r '.first_bad_seq // 0')
check "8b" "$([ "$OK2" = "false" ] && echo 1 || echo 0)" "篡改后：ok=$OK2 first_bad_seq=$BAD（必须失败）"

echo ""
if [ "$FAILS" -eq 0 ]; then
    echo "=== v0.5.0 新增能力全部通过 ==="
else
    echo "=== 失败 $FAILS 项 ==="
fi
exit "$FAILS"
