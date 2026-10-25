#!/bin/bash
set -e

# 可用 ESHIELD_TEST_XDP_MODE=skb 让所有 eShield 实例强制 SKB 模式，
# 规避 veth/虚拟网卡上原生 XDP_TX 可能触发的内核问题。
if [ -n "${ESHIELD_TEST_XDP_MODE:-}" ]; then
    export ESHIELD_XDP_MODE="$ESHIELD_TEST_XDP_MODE"
fi

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 在 sudo 环境下 $HOME / PATH 可能被重置，因此依次探测：显式变量 → PATH → $HOME → /root。
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
CARGO_ROOT="$(cd "$(dirname "$CARGO")/.." && pwd)"
RUSTUP="${RUSTUP:-$(dirname "$CARGO")/rustup}"
export PATH="$(dirname "$CARGO"):$PATH"
export RUSTUP_HOME="${RUSTUP_HOME:-$CARGO_ROOT/.rustup}"
export CARGO_HOME="${CARGO_HOME:-$CARGO_ROOT/.cargo}"

cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    echo "=== Building eShield ==="
    "$CARGO" +"$EBPF_TOOLCHAIN" build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
fi

# 确保没有旧进程占用测试二进制（只杀 /tmp/eshield，避免误伤宿主机上的生产实例）
pkill -9 -f '^/tmp/eshield( |$)' 2>/dev/null || true
sleep 0.5
rm -f /tmp/eshield /tmp/eshield.ebpf
cp "target/x86_64-unknown-linux-musl/release/eshield" /tmp/eshield
cp "target/bpfel-unknown-none/release/eshield" /tmp/eshield.ebpf

# 测试配置未指定 store_path，会写入宿主机默认路径。测试前备份、退出时恢复，
# 避免跑一次集成测试就把开发机/生产机上的动态规则清空。
STORE_FILE="/var/lib/eshield/rules.redb"
STORE_BAK=""
if [ -f "$STORE_FILE" ]; then
    STORE_BAK="$(mktemp /tmp/eshield-store-XXXXXX.bak)"
    cp -a "$STORE_FILE" "$STORE_BAK"
fi
mktemp_cfg=""
cleanup() {
    ip netns del eshield-client 2>/dev/null || true
    ip netns del eshield-server 2>/dev/null || true
    if [ -n "$STORE_BAK" ] && [ -f "$STORE_BAK" ]; then
        mv -f "$STORE_BAK" "$STORE_FILE" 2>/dev/null || true
    fi
    rm -f "$mktemp_cfg" /tmp/dummy_xdp.o /tmp/sc_recv1 /tmp/sc_recv2 2>/dev/null || true
}
trap cleanup EXIT

ip netns del eshield-client 2>/dev/null || true
ip netns del eshield-server 2>/dev/null || true
ip link del veth-server 2>/dev/null || true
ip link del veth-client 2>/dev/null || true

# 清理持久化规则存储，保证每次测试从干净状态开始
rm -f /var/lib/eshield/rules.redb

ip netns add eshield-server
ip netns add eshield-client
ip link add veth-server type veth peer name veth-client
ip link set veth-server netns eshield-server
ip link set veth-client netns eshield-client
ip -n eshield-server addr add 10.0.0.1/24 dev veth-server
ip -n eshield-client addr add 10.0.0.2/24 dev veth-client
ip -n eshield-server link set veth-server up
ip -n eshield-client link set veth-client up
ip -n eshield-server link set lo up
ip -n eshield-client link set lo up

# veth 原生 XDP_TX 要求对端接口也挂载 XDP 程序；挂载一个 dummy pass-through
# 程序，使 Test 1.5 的 TCP RST 回包能到达客户端。
if command -v clang >/dev/null 2>&1; then
    clang -O2 -target bpf -c "tests/dummy_xdp.c" -o /tmp/dummy_xdp.o
    ip -n eshield-client link set veth-client xdp obj /tmp/dummy_xdp.o sec xdp
else
    echo "WARNING: clang not found; Test 1.5 (tcp_reset_on_drop) may fail on veth"
fi

mktemp_cfg=$(mktemp /tmp/eshield-XXXXXX.toml)
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = ["10.0.0.2"]
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

echo "=== Test 1: blacklist source IP 10.0.0.2 should be dropped ==="
if ip netns exec eshield-client ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: blacklist IP was not dropped"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: blacklist IP dropped"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

echo "=== Test 1.5: tcp_reset_on_drop should reply TCP RST for dropped traffic ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "debug"
ebpf_log_enabled = true
whitelist = ["10.0.0.1/32"]
blacklist = ["10.0.0.2"]
tcp_reset_on_drop = true
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

ip netns exec eshield-server tcpdump -i veth-server -nn -c 5 -w /tmp/t15_server.pcap tcp port 12345 2>/dev/null &
SVR_DUMP=$!
ip netns exec eshield-client tcpdump -i veth-client -nn -c 5 -w /tmp/t15_client.pcap tcp port 12345 2>/dev/null &
CLI_DUMP=$!
sleep 1

start=$(date +%s%N)
set +e
ip netns exec eshield-client nc -w 2 -z 10.0.0.1 12345 >/dev/null 2>&1
NC_EXIT=$?
set -e
end=$(date +%s%N)
elapsed_ms=$(( (end - start) / 1000000 ))

sleep 1
kill $SVR_DUMP $CLI_DUMP 2>/dev/null || true

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

# RST causes immediate connection refused; silent drop causes nc to wait the full timeout.
if [ "$NC_EXIT" -ne 0 ] && [ "$elapsed_ms" -lt 1500 ]; then
    echo "PASS: TCP RST received for dropped connection (${elapsed_ms}ms)"
else
    echo "FAIL: expected RST (immediate refusal), got nc exit=$NC_EXIT elapsed=${elapsed_ms}ms"
    echo "--- server pcap ---"
    ip netns exec eshield-server tcpdump -nn -r /tmp/t15_server.pcap 2>/dev/null || true
    echo "--- client pcap ---"
    ip netns exec eshield-client tcpdump -nn -r /tmp/t15_client.pcap 2>/dev/null || true
    exit 1
fi

echo "=== Test 2: Per-IP rate limit should drop flood traffic ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = true
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 5
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 先确认正常 ping 可达
if ! ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: baseline ping failed before rate limit test"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 快速发送 20 个包，应触发阈值
ip netns exec eshield-client ping -c 20 -i 0.001 -W 2 10.0.0.1 >/dev/null 2>&1 || true
sleep 0.5

# 触发后应被加入黑名单，后续 ping 被丢弃
if ip netns exec eshield-client ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: rate limit did not drop subsequent traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: rate limit triggered and traffic dropped"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

echo "=== Test 3: SYN flood enters challenge mode; challenged source with TCP options is dropped ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
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

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 先确认正常 ping 可达
if ! ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: baseline ping failed before SYN flood test"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 发送 20 个 SYN 包触发 SYN flood 阈值，源 IP 进入 Cookie 挑战模式
ip netns exec eshield-client hping3 -S -p 80 -c 20 -i u10000 10.0.0.1 >/dev/null 2>&1 || true

# 通过 API 确认挑战确实触发：syn_flood_blocked 必须 > 0。
# 用户态每 1s 才从 eBPF map 同步一次统计，这里轮询最多 5s，避免读到全零快照。
SC_STATS=""
for _ in $(seq 1 10); do
    SC_STATS=$(ip netns exec eshield-server curl -s --max-time 3 http://127.0.0.1:8720/api/stats || true)
    if echo "$SC_STATS" | grep -q '"syn_flood_blocked":[1-9]'; then
        break
    fi
    sleep 0.5
done
if ! echo "$SC_STATS" | grep -q '"syn_flood_blocked":[1-9]'; then
    echo "FAIL: SYN flood challenge was not triggered (stats: $SC_STATS)"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi
echo "PASS: SYN flood challenge triggered"

# 语义说明（v0.4.8）：
# 挑战包只能构造 20/24 字节 TCP 头。Linux 客户端（nc）的 SYN 带 timestamps，
# 属"挑战态但无法挑战"的包头，会被直接 DROP（否则带选项的 SYN Flood 会直通内核）。
# 因此这里断言两件事：
#   1) 被挑战源 10.0.0.2 的后续连接被丢弃（不再直通）；
#   2) 未被挑战的另一个源 10.0.0.3 建立连接完全正常（不误伤其他业务）。
ip netns exec eshield-server nc -l 10.0.0.1 9002 > /tmp/sc_recv1 2>/dev/null &
NC_PID=$!
sleep 0.5
echo -n "CHALLENGED" | timeout 3 ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 9002 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

# 干净源（未被挑战）验证业务不受影响
ip -n eshield-client addr add 10.0.0.3/24 dev veth-client 2>/dev/null || true
ip netns exec eshield-server nc -l 10.0.0.1 9003 > /tmp/sc_recv2 2>/dev/null &
NC_PID=$!
sleep 0.5
echo -n "CLEAN" | timeout 3 ip netns exec eshield-client nc -s 10.0.0.3 -q 1 -w 2 10.0.0.1 9003 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

CHALLENGED_OUT=$(cat /tmp/sc_recv1 2>/dev/null)
CLEAN_OUT=$(cat /tmp/sc_recv2 2>/dev/null)
if [ "$CHALLENGED_OUT" = "CHALLENGED" ]; then
    echo "FAIL: 被挑战源的带选项 SYN 被直通（SYN Proxy 兜底未生效）"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi
if [ "$CLEAN_OUT" != "CLEAN" ]; then
    echo "FAIL: 未被挑战的干净源连接失败（误伤正常业务）"
    echo "clean: '$CLEAN_OUT'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi
echo "PASS: 被挑战源(带TCP选项)被丢弃，未挑战源连接正常"

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb /tmp/sc_recv1 /tmp/sc_recv2

echo "=== Test 4: L7 lightweight fingerprint scan should drop matching payload ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = true
patterns = [
    { pattern = "ATTACKER" }
]
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 启动服务端 nc 监听 8080，后台接收数据
rm -f /tmp/l7_server_recv
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/l7_server_recv &
NC_PID=$!
sleep 0.5

# 发送非匹配载荷，应被服务端收到
echo -n "HELLO" | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5

# 发送匹配载荷，应被 DROP
rm -f /tmp/l7_server_recv2
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/l7_server_recv2 &
NC_PID2=$!
sleep 0.5
echo -n "ATTACKER" | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5

kill $NC_PID $NC_PID2 2>/dev/null || true

if [ "$(cat /tmp/l7_server_recv)" = "HELLO" ] && [ "$(cat /tmp/l7_server_recv2)" = "" ]; then
    echo "PASS: L7 scan dropped matching payload and passed non-matching"
else
    echo "FAIL: L7 scan behavior unexpected"
    echo "recv1: '$(cat /tmp/l7_server_recv)'"
    echo "recv2: '$(cat /tmp/l7_server_recv2)'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb


echo "=== Test 5: after stopping eShield, ping should succeed ==="
if ip netns exec eshield-client ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "PASS: traffic restored after stopping eShield"
else
    echo "FAIL: traffic not restored"
    exit 1
fi

rm -f "$mktemp_cfg" /tmp/l7_server_recv /tmp/l7_server_recv2
echo "=== Test 6: SIGHUP config reload should update blacklist without restart ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false
TOML

cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

if ! ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: initial ping blocked before reload"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = ["10.0.0.2"]

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false
TOML

kill -HUP $ESHIELD_PID
sleep 2

if ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: ping still allowed after blacklist reload"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: SIGHUP reload applied new blacklist"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

echo "=== Test 7: adaptive threshold should block repeat offenders ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = true
patterns = [
    { pattern = "ATTACKER" }
]

[adaptive]
enabled = true
threshold = 2
window_s = 5
block_duration_s = 60
TOML

cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 先确认 ping 能通
if ! ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: initial ping blocked"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 触发 2 次 L7 DROP 事件，使自适应阈值引擎封禁 10.0.0.2
for _ in 1 2; do
    ip netns exec eshield-server nc -l 10.0.0.1 8080 >/dev/null &
    NC_PID=$!
    sleep 0.3
    echo -n "ATTACKER" | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
    sleep 0.3
    kill $NC_PID 2>/dev/null || true
done

sleep 1

# 此时应已被自适应黑名单封禁
if ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: adaptive threshold did not block repeat offender"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: adaptive threshold blocked repeat offender"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

rm -f "$mktemp_cfg" /tmp/l7_server_recv /tmp/l7_server_recv2


echo "=== Test 8: GeoIP/ASN CIDR block should drop matching source network ==="
cat > /tmp/geoip_country.csv <<'EOF'
network,country_iso
10.0.0.0/24,XX
EOF
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[geoip]
enabled = true
country_blocks_csv = "/tmp/geoip_country.csv"
block_countries = ["XX"]
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 3

if ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: GeoIP CIDR block did not drop traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: GeoIP CIDR block dropped traffic"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb
rm -f /tmp/geoip_country.csv

echo "=== Test 9: Threat intel feed should block listed IP ==="
mkdir -p /tmp/ti-feed
cat > /tmp/ti-feed/feed.txt <<'EOF'
# test threat feed
10.0.0.2
EOF

# 在 server netns 中启动一个简单 HTTP server 提供 feed
ip netns exec eshield-server python3 -m http.server 8081 --directory /tmp/ti-feed >/dev/null 2>&1 &
HTTP_PID=$!
sleep 1

cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[threat_intel]
enabled = true

[[threat_intel.feeds]]
name = "test-feed"
url = "http://10.0.0.1:8081/feed.txt"
interval_s = 5
action = "drop"
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 8

if ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: threat intel feed did not drop traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    kill $HTTP_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: threat intel feed dropped traffic"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
kill $HTTP_PID 2>/dev/null || true
wait $HTTP_PID 2>/dev/null || true
rm -rf /tmp/ti-feed
# 清理威胁情报产生的持久化黑名单，避免污染后续防护项目测试
rm -f /var/lib/eshield/rules.redb

echo "=== Test 10: protection project DROP should block matching dst port ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[[protection_projects]]
name = "drop-web"
description = "drop tcp 8080 to server"
protocol = "tcp"
dport = "8080"
target_ips = ["10.0.0.1/32"]
action = "drop"
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 8080 命中项目 DROP：数据无法送达
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/pp_recv_drop 2>/dev/null &
NC_PID=$!
sleep 0.5
echo -n "HI" | timeout 3 ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

# 8081 未匹配项目：正常可达
ip netns exec eshield-server nc -l 10.0.0.1 8081 > /tmp/pp_recv_ok 2>/dev/null &
NC_PID=$!
sleep 0.5
echo -n "OK" | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8081 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

if [ "$(cat /tmp/pp_recv_drop 2>/dev/null)" = "" ] && [ "$(cat /tmp/pp_recv_ok 2>/dev/null)" = "OK" ]; then
    echo "PASS: protection project DROP blocked 8080, 8081 unaffected"
else
    echo "FAIL: protection project behavior unexpected"
    echo "drop: '$(cat /tmp/pp_recv_drop 2>/dev/null)'"
    echo "ok: '$(cat /tmp/pp_recv_ok 2>/dev/null)'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb /tmp/pp_recv_drop /tmp/pp_recv_ok

echo "=== Test 11: SYN Cookie disabled path keeps real handshake transparent ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = true

[l7_scan]
enabled = false
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 高阈值（默认 200）下正常握手不应被挑战，保持透明
ip netns exec eshield-server nc -l 10.0.0.1 9010 > /tmp/sc_base 2>/dev/null &
NC_PID=$!
sleep 0.5
echo -n "BASELINE" | timeout 3 ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 9010 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

if [ "$(cat /tmp/sc_base 2>/dev/null)" = "BASELINE" ]; then
    echo "PASS: normal handshake transparent under SYN Cookie proxy"
else
    echo "FAIL: normal handshake broken under SYN Cookie proxy"
    echo "base: '$(cat /tmp/sc_base 2>/dev/null)'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb /tmp/sc_base



echo "=== Test 12: GeoIP allowlist + default_action=drop + fragmented traffic ==="
cat > /tmp/geoip_allow.csv <<'EOF'
network,country_iso
10.0.0.2/32,CN
EOF
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[geoip]
enabled = true
country_blocks_csv = "/tmp/geoip_allow.csv"
allow_countries = ["CN"]
default_action = "drop"
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 10.0.0.2 在 allow 列表（10.0.0.0/24,CN）内：普通包与大包分片都应放行
if ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 &&    ip netns exec eshield-client ping -s 2000 -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "PASS: GeoIP allowlist permitted listed source (including fragments)"
else
    echo "FAIL: GeoIP allowlist dropped listed source or fragmented traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 10.0.0.3 不在 allow 列表：default_action=drop 应丢弃
ip netns exec eshield-client ip addr add 10.0.0.3/24 dev veth-client 2>/dev/null || true
if ip netns exec eshield-client ping -I 10.0.0.3 -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: GeoIP default_action=drop did not drop non-allowlisted source"
    ip netns exec eshield-client ip addr del 10.0.0.3/24 dev veth-client 2>/dev/null || true
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: GeoIP default_action=drop blocked non-allowlisted source"
fi
ip netns exec eshield-client ip addr del 10.0.0.3/24 dev veth-client 2>/dev/null || true

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb /tmp/geoip_allow.csv

echo "=== Test 13: optional connection tracking should block SYN flood, keep ICMP ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[conn_track]
enabled = true
threshold = 2
window_ms = 5000
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 2

# 3 个未完成握手的 SYN，阈值 2，应触发连接跟踪 DROP
ip netns exec eshield-client hping3 -S -p 80 -c 3 -i u10000 10.0.0.1 >/dev/null 2>&1 || true

# 同样轮询等待用户态同步 eBPF 统计。
CT_STATS=""
for _ in $(seq 1 10); do
    CT_STATS=$(ip netns exec eshield-server curl -s --max-time 3 http://127.0.0.1:8720/api/stats || true)
    if echo "$CT_STATS" | grep -q '"conn_track_blocked":[1-9]'; then
        break
    fi
    sleep 0.5
done
if ! echo "$CT_STATS" | grep -q '"conn_track_blocked":[1-9]'; then
    echo "FAIL: conn_track did not block half-open SYN flood (stats: $CT_STATS)"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# ICMP 不属于 TCP，连接跟踪不应误伤
if ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "PASS: conn_track blocked half-open SYNs, ICMP unaffected"
else
    echo "FAIL: conn_track blocked non-TCP traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1
rm -f /var/lib/eshield/rules.redb

echo "=== All Phase 1+2+3 integration tests passed ==="
