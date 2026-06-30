#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

# 在 sudo 环境下 $HOME 可能变成 /root，因此显式指向 ubuntu 用户的 Rust 环境
CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
RUSTUP="${RUSTUP:-/home/ubuntu/.cargo/bin/rustup}"
export PATH="/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/ubuntu/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/home/ubuntu/.cargo}"

cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    echo "=== Building eShield ==="
    "$CARGO" +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
fi

# 确保没有旧进程占用测试二进制
pkill -9 -x eshield 2>/dev/null || true
sleep 0.5
rm -f /tmp/eshield /tmp/eshield.ebpf
cp "target/x86_64-unknown-linux-musl/release/eshield" /tmp/eshield
cp "target/bpfel-unknown-none/release/eshield" /tmp/eshield.ebpf

cleanup() {
    ip netns del eshield-client 2>/dev/null || true
    ip netns del eshield-server 2>/dev/null || true
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

echo "=== Test 3: SYN flood detection should drop SYN flood source ==="
cat > "$mktemp_cfg" <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = false
threshold = 5
tick_ms = 100

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

# 发送 20 个 SYN 包触发 SYN flood 阈值
ip netns exec eshield-client hping3 -S -p 80 -c 20 -i u10000 10.0.0.1 >/dev/null 2>&1 || true
sleep 0.5

# 触发后源 IP 应被加黑名单，后续 ping 被丢弃
if ip netns exec eshield-client ping -c 3 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: SYN flood did not drop subsequent traffic"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
else
    echo "PASS: SYN flood detected and traffic dropped"
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1

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


echo "=== Test 4.5: HTTP WAF should drop matching URI ==="
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

[waf]
enabled = true
rules = [
    { name = "block-admin", enabled = true, priority = 1, action = "drop", match = { method = "GET", path_prefix = "/admin" } }
]
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 3

rm -f /tmp/waf_recv1 /tmp/waf_recv2
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/waf_recv1 &
NC_PID=$!
sleep 0.5
printf 'GET /ok HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n' | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/waf_recv2 &
NC_PID2=$!
sleep 0.5
printf 'GET /admin HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n' | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5
kill $NC_PID2 2>/dev/null || true

expected1=$(printf 'GET /ok HTTP/1.1\r\nHost: example.com\r\nUser-Agent: test\r\n\r\n')
if [ "$(cat /tmp/waf_recv1)" = "$expected1" ] && [ "$(cat /tmp/waf_recv2)" = "" ]; then
    echo "PASS: WAF dropped matching URI and passed non-matching"
else
    echo "FAIL: WAF behavior unexpected"
    echo "recv1: '$(cat /tmp/waf_recv1)'"
    echo "recv2: '$(cat /tmp/waf_recv2)'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1

echo "=== Test 4.6: WAF Challenge should drop matching request and allow pass via challenge page ==="
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

[waf]
enabled = true
rules = [
    { name = "challenge-secret", enabled = true, priority = 1, action = "challenge", match = { method = "GET", path_prefix = "/secret" } }
]

[challenge]
enabled = true
ttl_s = 60
TOML

ip netns exec eshield-server /tmp/eshield start --config "$mktemp_cfg" &
ESHIELD_PID=$!
sleep 3

# 第一次访问 /secret 应被 Challenge DROP
rm -f /tmp/challenge_recv1
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/challenge_recv1 &
NC_PID=$!
sleep 0.5
printf 'GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n' | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5
kill $NC_PID 2>/dev/null || true

if [ "$(cat /tmp/challenge_recv1)" != "" ]; then
    echo "FAIL: challenge request was not dropped"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 通过 challenge 页面获取 nonce 并验证
CHALLENGE_HTML=$(ip netns exec eshield-client curl -s http://10.0.0.1:8443/challenge)
NONCE=$(echo "$CHALLENGE_HTML" | grep -oP 'id="nonce" value="\K[^"]+' || true)
if [ -z "$NONCE" ]; then
    echo "FAIL: failed to extract challenge nonce"
    echo "$CHALLENGE_HTML"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi
A=$(echo "$NONCE" | cut -d: -f1)
B=$(echo "$NONCE" | cut -d: -f2)
ANSWER=$(echo "$A + $B" | bc)

PASS_RESP=$(ip netns exec eshield-client curl -s -X POST http://10.0.0.1:8443/api/challenge/pass \
    -H 'Content-Type: application/json' \
    -d "{\"ip\":\"10.0.0.2\",\"nonce\":\"$NONCE\",\"answer\":$ANSWER}")
if ! echo "$PASS_RESP" | grep -q "验证通过"; then
    echo "FAIL: challenge pass failed: $PASS_RESP"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

# 验证通过后再次访问 /secret 应被服务端收到
rm -f /tmp/challenge_recv2
ip netns exec eshield-server nc -l 10.0.0.1 8080 > /tmp/challenge_recv2 &
NC_PID2=$!
sleep 0.5
printf 'GET /secret HTTP/1.1\r\nHost: example.com\r\n\r\n' | ip netns exec eshield-client nc -q 1 -w 2 10.0.0.1 8080 || true
sleep 0.5
kill $NC_PID2 2>/dev/null || true

if echo "$(cat /tmp/challenge_recv2)" | grep -q "GET /secret"; then
    echo "PASS: WAF Challenge dropped request and allowed pass via challenge page"
else
    echo "FAIL: challenge allow did not unblock request"
    echo "recv2: '$(cat /tmp/challenge_recv2)'"
    kill $ESHIELD_PID 2>/dev/null || true
    exit 1
fi

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
sleep 1

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



echo "=== All Phase 1+2+3 integration tests passed ==="
