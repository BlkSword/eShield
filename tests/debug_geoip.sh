#!/bin/bash
# GeoIP debug helper: builds, sets up netns, dumps the map and reads trace_pipe.
set -e

CARGO="${CARGO:-/home/ubuntu/.cargo/bin/cargo}"
export PATH="/home/ubuntu/.cargo/bin:$PATH"
export RUSTUP_HOME="${RUSTUP_HOME:-/home/ubuntu/.rustup}"
export CARGO_HOME="${CARGO_HOME:-/home/ubuntu/.cargo}"

cd "$(dirname "$0")/.."

echo "=== Building ==="
"$CARGO" +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
"$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q

echo "=== Setting up netns ==="
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

TMPDIR=$(mktemp -d /tmp/eshield-geoip-XXXXXX)
chmod 755 "$TMPDIR"

cat > "$TMPDIR/geoip_country.csv" <<'EOF'
network,country_iso
10.0.0.0/24,XX
EOF

cat > "$TMPDIR/eshield-geoip.toml" <<'TOML'
interface = "veth-server"
log_level = "info"
ebpf_log_enabled = true
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
country_blocks_csv = "GEOIP_CSV_PATH"
block_countries = ["XX"]
TOML
sed -i "s|GEOIP_CSV_PATH|$TMPDIR/geoip_country.csv|g" "$TMPDIR/eshield-geoip.toml"

cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
cp target/bpfel-unknown-none/release/eshield /tmp/eshield.ebpf

echo "=== Mounting debugfs ==="
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
> /sys/kernel/debug/tracing/trace_pipe || true

echo "=== Starting eShield ==="
ESHIELD_LOG="$TMPDIR/eshield.log"
export RUST_LOG=debug
ip netns exec eshield-server /tmp/eshield start --config "$TMPDIR/eshield-geoip.toml" >"$ESHIELD_LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "=== GEOIP_BLOCKED_V4 map ==="
bpftool map list | grep -i geoip || true
echo "--- dump ---"
bpftool map dump name GEOIP_BLOCKED_V4 2>/dev/null || true

echo "=== CONFIG runtime ==="
bpftool map dump name CONFIG 2>/dev/null || true

echo "=== Pinging from client (should be dropped) ==="
ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 || true

sleep 1
echo "=== eShield log (last 80 lines) ==="
tail -n 80 "$ESHIELD_LOG" 2>/dev/null || true

echo "=== trace_pipe ==="
timeout 2 cat /sys/kernel/debug/tracing/trace_pipe || true

echo "=== Cleanup ==="
kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
ip netns del eshield-client 2>/dev/null || true
ip netns del eshield-server 2>/dev/null || true
rm -rf "$TMPDIR"
