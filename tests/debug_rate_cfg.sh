#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then echo "请使用 sudo"; exit 1; fi

cleanup() {
    kill $ESHIELD_PID 2>/dev/null || true
    wait $ESHIELD_PID 2>/dev/null || true
    ip netns del es-dbg-c 2>/dev/null || true
    ip netns del es-dbg-s 2>/dev/null || true
    rm -f /tmp/es-dbg.toml /tmp/es-dbg.redb
}
trap cleanup EXIT

ip netns del es-dbg-c 2>/dev/null || true
ip netns del es-dbg-s 2>/dev/null || true
ip netns add es-dbg-s
ip netns add es-dbg-c
ip link add vs-dbg type veth peer name vc-dbg
ip link set vs-dbg netns es-dbg-s
ip link set vc-dbg netns es-dbg-c
ip netns exec es-dbg-s ip addr add 10.9.9.1/24 dev vs-dbg
ip netns exec es-dbg-c ip addr add 10.9.9.2/24 dev vc-dbg
ip netns exec es-dbg-s ip link set vs-dbg up
ip netns exec es-dbg-c ip link set vc-dbg up

cat > /tmp/es-dbg.toml <<'EOF'
interface = "vs-dbg"
web_bind = "0.0.0.0:8443"
log_level = "info"
store_path = "/tmp/es-dbg.redb"
blacklist = []
whitelist = ["10.9.9.1/32"]
[rate_limit]
enabled = true
threshold = 12345
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 60
[adaptive]
enabled = false
EOF

ip netns exec es-dbg-s ./target/x86_64-unknown-linux-musl/release/eshield start --config /tmp/es-dbg.toml >/tmp/es-dbg.log 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "=== bpftool maps ==="
bpftool map show | grep -i rate || true
echo ""
echo "=== dump RATE_LIMIT_CFG (looking for map name) ==="
MAP_ID=$(bpftool map show | grep -i 'RATE_LIMIT_CFG' | head -1 | awk -F: '{print $1}')
if [ -n "$MAP_ID" ]; then
    echo "MAP_ID=$MAP_ID"
    bpftool map dump id "$MAP_ID"
else
    echo "RATE_LIMIT_CFG map not found"
fi

echo ""
echo "=== /api/config rate_limit ==="
ip netns exec es-dbg-s curl -s http://127.0.0.1:8443/api/config | jq .rate_limit
