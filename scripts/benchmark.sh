#!/bin/bash
# eShield XDP 吞吐量基准测试
# 在 netns 中对比：无 eShield、XDP PASS、XDP DROP 三种场景
set -e

PACKETS="${PACKETS:-200000}"
INTERVAL="${INTERVAL:-u1}"
PORT="${PORT:-80}"

cleanup() {
    ip netns del eshield-server 2>/dev/null || true
    ip netns del eshield-client 2>/dev/null || true
    rm -f /tmp/eshield_bench.toml
}
trap cleanup EXIT

setup_netns() {
    ip netns add eshield-server
    ip netns add eshield-client

    ip link add veth-server type veth peer name veth-client
    ip link set veth-server netns eshield-server
    ip link set veth-client netns eshield-client

    ip netns exec eshield-server ip addr add 10.0.0.1/24 dev veth-server
    ip netns exec eshield-client ip addr add 10.0.0.2/24 dev veth-client

    ip netns exec eshield-server ip link set veth-server up
    ip netns exec eshield-client ip link set veth-client up
    ip netns exec eshield-server ip link set lo up
    ip netns exec eshield-client ip link set lo up
}

run_hping() {
    local label=$1
    echo "--- $label ---"
    local start end elapsed pps
    start=$(date +%s%N)
    ip netns exec eshield-client hping3 -S -p "$PORT" -c "$PACKETS" -i "$INTERVAL" 10.0.0.1 >/dev/null 2>&1 || true
    end=$(date +%s%N)
    elapsed=$(( (end - start) ))
    if [ "$elapsed" -eq 0 ]; then elapsed=1; fi
    # pps = packets / (ns / 1e9)
    pps=$(awk "BEGIN { printf \"%.0f\", $PACKETS / ($elapsed / 1000000000) }")
    echo "  packets: $PACKETS, time: $(awk "BEGIN { printf \"%.3f\", $elapsed / 1000000000 }")s, pps: $pps"
}

write_config() {
    local blacklist=$1
    cat > /tmp/eshield_bench.toml <<EOF
interface = "veth-server"
log_level = "warn"
whitelist = ["10.0.0.1/32"]
blacklist = [$blacklist]
web_port = 0

[rate_limit]
enabled = false

[syn_proxy]
enabled = false

[l7_scan]
enabled = false

[adaptive]
enabled = false
EOF
}

main() {
    if [ "$EUID" -ne 0 ]; then
        echo "请使用 sudo 运行"
        exit 1
    fi

    if ! command -v hping3 >/dev/null 2>&1; then
        echo "需要安装 hping3"
        exit 1
    fi

    echo "=== eShield XDP Benchmark ==="
    echo "packets: $PACKETS, interval: $INTERVAL"

    setup_netns

    echo ""
    run_hping "Baseline (no eShield)"

    write_config ""
    cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
    ip netns exec eshield-server /tmp/eshield start --config /tmp/eshield_bench.toml &
    ESHIELD_PID=$!
    sleep 2
    run_hping "XDP PASS (no drop rules)"
    kill $ESHIELD_PID 2>/dev/null || true
    wait $ESHIELD_PID 2>/dev/null || true
    sleep 1

    write_config '"10.0.0.2"'
    ip netns exec eshield-server /tmp/eshield start --config /tmp/eshield_bench.toml &
    ESHIELD_PID=$!
    sleep 2
    run_hping "XDP DROP (blacklist source)"
    kill $ESHIELD_PID 2>/dev/null || true
    wait $ESHIELD_PID 2>/dev/null || true

    echo ""
    echo "=== Benchmark complete ==="
}

main "$@"
