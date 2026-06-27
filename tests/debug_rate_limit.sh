#!/bin/bash
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

TMPDIR=$(mktemp -d /tmp/eshield-rl-XXXXXX)
chmod 755 "$TMPDIR"

cat > "$TMPDIR/rl.toml" <<'TOML'
interface = "veth-server"
log_level = "info"
ebpf_log_enabled = true
whitelist = ["10.0.0.1/32"]
blacklist = []

[rate_limit]
enabled = true
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 5

[syn_proxy]
enabled = false

[l7_scan]
enabled = false
TOML

cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
cp target/bpfel-unknown-none/release/eshield /tmp/eshield.ebpf

export RUST_LOG=debug
ESHIELD_LOG="$TMPDIR/eshield.log"
ip netns exec eshield-server /tmp/eshield start --config "$TMPDIR/rl.toml" >"$ESHIELD_LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "=== Baseline ping ==="
ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 || true

echo "=== eShield log ==="
tail -n 60 "$ESHIELD_LOG"

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
ip netns del eshield-client 2>/dev/null || true
ip netns del eshield-server 2>/dev/null || true
rm -rf "$TMPDIR"
