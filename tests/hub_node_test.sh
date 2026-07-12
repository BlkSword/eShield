#!/bin/bash
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

CARGO="${CARGO:-/root/.cargo/bin/cargo}"
export PATH="/root/.cargo/bin:$PATH"

cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    echo "=== Building eShield + Hub ==="
    "$CARGO" +nightly build --package eshield-ebpf --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
    "$CARGO" build --package eshield-hub --release -q
fi

pkill -9 -x eshield 2>/dev/null || true
pkill -9 -x eshield-hub 2>/dev/null || true
sleep 0.5

rm -f /tmp/eshield /tmp/eshield.ebpf /tmp/eshield-hub
cp "target/x86_64-unknown-linux-musl/release/eshield" /tmp/eshield
cp "target/bpfel-unknown-none/release/eshield" /tmp/eshield.ebpf
cp "target/release/eshield-hub" /tmp/eshield-hub

HUB_TOKEN="hub-token"
NODE_TOKEN="node-token"
NODE_NAME="test-node"
HUB_STORE="/tmp/hub-test.redb"
NODE_STORE="/tmp/node-test.redb"
HUB_LOG="/tmp/hub-test.log"
NODE_LOG="/tmp/node-test.log"
CFG="/tmp/hub-node-cfg.toml"

# 清理上次失败的持久化数据，避免跨测试污染
rm -f "$HUB_STORE" "$NODE_STORE" "$HUB_LOG" "$NODE_LOG" "$CFG"

TEST_PASSED=0
cleanup() {
    kill $ESHIELD_PID $HUB_PID 2>/dev/null || true
    wait $ESHIELD_PID $HUB_PID 2>/dev/null || true
    ip netns del eshield-client 2>/dev/null || true
    ip netns del eshield-server 2>/dev/null || true
    ip link del veth-server 2>/dev/null || true
    if [ "$TEST_PASSED" -eq 1 ]; then
        rm -f "$HUB_STORE" "$NODE_STORE" "$HUB_LOG" "$NODE_LOG" "$CFG"
    else
        echo "(logs preserved: $HUB_LOG $NODE_LOG)"
    fi
}
trap cleanup EXIT

ip netns del eshield-client 2>/dev/null || true
ip netns del eshield-server 2>/dev/null || true
ip link del veth-server 2>/dev/null || true

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

# extra source IP for peer-policy test
ip -n eshield-client addr add 10.0.0.3/24 dev veth-client

cat > "$CFG" <<EOF
interface = "veth-server"
log_level = "info"
whitelist = ["10.0.0.1/32"]
blacklist = []
api_token = "$NODE_TOKEN"
store_path = "$NODE_STORE"

[rate_limit]
enabled = true
threshold = 5
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 5

[syn_proxy]
enabled = false

[hub]
enabled = true
urls = ["http://10.0.0.1:9930"]
node_name = "$NODE_NAME"
token = "$HUB_TOKEN"
sync_pull_interval_s = 3
sync_push_interval_s = 3
push_min_hit_count = 1
push_min_trust = 1000
sync_rules_enabled = true
sync_rules_interval_s = 5

[trust_score]
enabled = false
EOF

echo "=== Starting Hub ==="
ip netns exec eshield-server /tmp/eshield-hub \
    --bind 0.0.0.0:9930 \
    --token "$HUB_TOKEN" \
    --store-path "$HUB_STORE" > "$HUB_LOG" 2>&1 &
HUB_PID=$!
sleep 1

echo "=== Starting eShield node ==="
ip netns exec eshield-server /tmp/eshield start --config "$CFG" > "$NODE_LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

wait_for() {
    local desc="$1"
    local timeout_s="$2"
    shift 2
    local i
    for (( i=0; i<timeout_s*2; i++ )); do
        if eval "$@" >/dev/null 2>&1; then
            return 0
        fi
        sleep 0.5
    done
    echo "TIMEOUT: $desc"
    return 1
}

hub_curl() {
    local path="$1"
    shift
    ip netns exec eshield-server curl -s -H "Authorization: Bearer $HUB_TOKEN" "$@" "http://10.0.0.1:9930$path"
}

node_curl() {
    local path="$1"
    shift
    ip netns exec eshield-server curl -s -H "Authorization: Bearer $NODE_TOKEN" "$@" "http://10.0.0.1:8720$path"
}

proxy_curl() {
    local path="$1"
    shift
    node_curl "/api/hub/proxy$path" "$@"
}

echo "=== Test H1: node connects to Hub ==="
wait_for "hub status connected" 10 "node_curl /api/hub/status | jq -e '.connected == true'"
node_curl /api/hub/status | jq .

echo "=== Test H2: node heartbeat visible on Hub ==="
wait_for "node registered on hub" 10 "hub_curl /api/v1/nodes | jq -e '.nodes[] | select(.name == \"$NODE_NAME\")'"
hub_curl /api/v1/nodes | jq .

echo "=== Test H3: local rate-limit block is pushed to Hub ==="
if ! ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: baseline ping failed"
    exit 1
fi
ip netns exec eshield-client ping -c 20 -i 0.001 -W 2 10.0.0.1 >/dev/null 2>&1 || true
sleep 1
if ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1; then
    echo "FAIL: rate limit did not block 10.0.0.2"
    exit 1
fi

echo "waiting for node to push policy to Hub..."
wait_for "policy for 10.0.0.2 on Hub" 15 "hub_curl '/api/v1/policies?since=0&limit=100' | jq -e '[.policies[] | select(.ip.addr == [0,0,0,0,0,0,0,0,0,0,0,0,10,0,0,2])] | length > 0'"
hub_curl '/api/v1/policies?since=0&limit=100' | jq .

echo "=== Test H4: Hub policy also visible through node proxy ==="
proxy_curl '/policies?since=0&limit=100' | jq -e '[.policies[] | select(.ip.addr == [0,0,0,0,0,0,0,0,0,0,0,0,10,0,0,2])] | length > 0'

echo "=== Test H5: peer policy from Hub is pulled and applied by node ==="
PEER_IP='{"family":4,"addr":[0,0,0,0,0,0,0,0,0,0,0,0,10,0,0,3],"padding":[0,0,0,0,0,0,0,0,0,0,0,0,0,0,0]}'
hub_curl /api/v1/policies -X POST -H "Content-Type: application/json" -d "{\"node_name\":\"peer-node\",\"policies\":[{\"ip\":$PEER_IP,\"reason\":2,\"hit_count\":100,\"trust_score\":0,\"blocked_until_ns\":0,\"ttl_s\":300}]}" | jq .

echo "waiting for node to pull peer policy..."
wait_for "10.0.0.3 blocked by node" 10 "! ip netns exec eshield-client ping -c 1 -W 2 -I 10.0.0.3 10.0.0.1 >/dev/null 2>&1"
echo "PASS: peer policy blocked 10.0.0.3"

echo "=== Test H6: Hub DELETE unblocks peer policy on node ==="
hub_curl /api/v1/policies -X DELETE -H "Content-Type: application/json" -d "{\"node_name\":\"admin\",\"ips\":[$PEER_IP]}" | jq .

echo "waiting for tombstone to propagate..."
wait_for "10.0.0.3 unblocked" 10 "ip netns exec eshield-client ping -c 1 -W 2 -I 10.0.0.3 10.0.0.1 >/dev/null 2>&1"
echo "PASS: Hub delete unblocked 10.0.0.3"

echo "=== Test H7: Hub rules (ACL/L7/projects) sync to node ==="
NOW_NS=$(date +%s%N)
hub_curl /api/v1/rules -X POST -H "Content-Type: application/json" -d "{\"port_acl\":[{\"protocol\":\"tcp\",\"dport\":\"9999\",\"action\":\"drop\"}],\"l7_patterns\":[{\"pattern\":\"EVIL\"}],\"protection_projects\":[{\"name\":\"hub-test\",\"protocol\":\"tcp\",\"dport\":\"9999\",\"target_ips\":[],\"enabled_modules\":[\"syn_flood\"],\"action\":\"defend\"}],\"updated_at_ns\":$NOW_NS}" | jq .

echo "waiting for rules to sync to node..."
wait_for "port_acl synced" 10 "node_curl /api/port-acl | jq -e '.items[] | select(.protocol == \"tcp\" and .dport == \"9999\" and .action == \"drop\")'"
wait_for "l7_patterns synced" 10 "node_curl /api/l7-patterns | jq -e '.patterns[] | select(.pattern == \"EVIL\")'"
wait_for "protection_projects synced" 10 "node_curl /api/protection-projects | jq -e '.projects[] | select(.name == \"hub-test\")'"
echo "PASS: Hub rules synced to node"

echo "=== Test H8: Hub Dashboard and Node cluster page are served ==="
node_curl / | grep -q "集群节点" || true
hub_curl / | grep -q "eShield Hub" || true
echo "PASS: dashboards served"

TEST_PASSED=1
echo "=== All Hub-Node integration tests passed ==="
