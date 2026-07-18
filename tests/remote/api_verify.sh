#!/bin/bash
set -e
set -o pipefail

export PATH=/root/.cargo/bin:$PATH
export RUSTUP_HOME=/root/.rustup
export CARGO_HOME=/root/.cargo

cd /tmp/eshield-sync

echo "=== Building ==="
cargo +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
cargo build --package eshield --target x86_64-unknown-linux-musl --release -q

echo "=== Setup test environment ==="
pkill -9 -x eshield 2>/dev/null || true
sleep 0.5
rm -f /tmp/eshield /tmp/eshield.ebpf /var/lib/eshield/rules.redb

cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
cp target/bpfel-unknown-none/release/eshield /tmp/eshield.ebpf

cleanup() {
    kill $CPU_MON_PID 2>/dev/null || true
    wait $CPU_MON_PID 2>/dev/null || true
    kill $ESHIELD_PID 2>/dev/null || true
    wait $ESHIELD_PID 2>/dev/null || true
    ip netns del eshield-client 2>/dev/null || true
    ip netns del eshield-server 2>/dev/null || true
    rm -f /tmp/eshield-api-test.toml /tmp/api_test_inner.sh
}
trap cleanup EXIT

ip netns del eshield-client 2>/dev/null || true
ip netns del eshield-server 2>/dev/null || true
ip link del veth-server 2>/dev/null || true
ip link del veth-client 2>/dev/null || true

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
ip -n eshield-server sysctl -w net.ipv6.conf.veth-server.disable_ipv6=1 >/dev/null 2>&1 || true
ip -n eshield-client sysctl -w net.ipv6.conf.veth-client.disable_ipv6=1 >/dev/null 2>&1 || true
ip -n eshield-server sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true
ip -n eshield-client sysctl -w net.ipv6.conf.all.disable_ipv6=1 >/dev/null 2>&1 || true

cat > /tmp/eshield-api-test.toml <<'TOML'
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = ["10.0.0.2"]
api_bind = "0.0.0.0:8720"
timeseries_retention_days = 7

[packet_log]
enabled = true
sample_rate = 10000
memory_max_entries = 1000
TOML

echo "=== Starting eshield ==="
ip netns exec eshield-server /tmp/eshield start --config /tmp/eshield-api-test.toml &
ESHIELD_PID=$!
sleep 3

# 后台监控 eshield CPU 使用率
(
  for i in $(seq 1 30); do
    ps -p $ESHIELD_PID -o %cpu=,rss= 2>/dev/null | awk -v t="$i" '{print "cpu_monitor t=" t " cpu=" $1 " rss=" $2}'
    sleep 1
  done
) &
CPU_MON_PID=$!

cat > /tmp/api_test_inner.sh <<'INNER'
#!/bin/bash
set -e
set -o pipefail
API="curl -s -m 3"

echo "=== /api/config ==="
$API http://127.0.0.1:8720/api/config

echo ""
echo ""
echo "=== /api/stats (baseline) ==="
$API http://127.0.0.1:8720/api/stats

echo ""
echo ""
echo "=== Generating blacklisted traffic ==="
ip netns exec eshield-client ping -c 5 -W 1 -i 0.2 10.0.0.1 >/dev/null 2>&1 || true
sleep 1

echo "=== /api/stats (after ping) ==="
$API http://127.0.0.1:8720/api/stats

echo ""
echo ""
echo "=== /api/packets?limit=20 ==="
$API "http://127.0.0.1:8720/api/packets?limit=20"

echo ""
echo ""
echo "=== /api/packets?ip=10.0.0.2&limit=10 ==="
$API "http://127.0.0.1:8720/api/packets?ip=10.0.0.2&limit=10"

echo ""
echo ""
echo "=== /api/ip-detail?ip=10.0.0.2 ==="
$API "http://127.0.0.1:8720/api/ip-detail?ip=10.0.0.2"

echo ""
echo ""
echo "=== /api/ip-series?ip=10.0.0.2 ==="
$API "http://127.0.0.1:8720/api/ip-series?ip=10.0.0.2"

echo ""
echo ""
echo "=== /api/metrics/series ==="
$API http://127.0.0.1:8720/api/metrics/series

echo ""
echo ""
echo "=== API verification complete ==="
INNER
chmod +x /tmp/api_test_inner.sh

echo "=== Running API checks inside namespace ==="
ip netns exec eshield-server bash /tmp/api_test_inner.sh
