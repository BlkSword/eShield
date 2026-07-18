#!/bin/bash
set -u
cd /tmp/eshield-sync
pkill -9 -x eshield 2>/dev/null; pkill -9 -x eshield-hub 2>/dev/null; sleep 0.5
ip netns del eshield-client 2>/dev/null; ip netns del eshield-server 2>/dev/null; ip link del veth-server 2>/dev/null
rm -f /tmp/hub-test.redb /tmp/node-test.redb /tmp/h3-hub.log /tmp/h3-node.log /tmp/h3-cfg.toml
cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield
cp target/release/eshield-hub /tmp/eshield-hub

ip netns add eshield-server; ip netns add eshield-client
ip link add veth-server type veth peer name veth-client
ip link set veth-server netns eshield-server
ip link set veth-client netns eshield-client
ip -n eshield-server addr add 10.0.0.1/24 dev veth-server
ip -n eshield-client addr add 10.0.0.2/24 dev veth-client
ip -n eshield-server link set veth-server up
ip -n eshield-client link set veth-client up
ip -n eshield-server link set lo up
ip -n eshield-client link set lo up

cat > /tmp/h3-cfg.toml <<'CFG'
interface = "veth-server"
log_level = "debug"
whitelist = ["10.0.0.1/32"]
blacklist = []
api_token = "node-token"
store_path = "/tmp/node-test.redb"
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
node_name = "test-node"
token = "hub-token"
sync_pull_interval_s = 3
sync_push_interval_s = 3
push_min_hit_count = 1
push_min_trust = 1000
sync_rules_enabled = true
sync_rules_interval_s = 5
[trust_score]
enabled = false
CFG

ip netns exec eshield-server /tmp/eshield-hub --bind 0.0.0.0:9930 --token hub-token --store-path /tmp/hub-test.redb > /tmp/h3-hub.log 2>&1 &
sleep 1
ip netns exec eshield-server /tmp/eshield start --config /tmp/h3-cfg.toml > /tmp/h3-node.log 2>&1 &
sleep 3

echo "--- baseline ping:"; ip netns exec eshield-client ping -c 1 -W 2 10.0.0.1 >/dev/null 2>&1 && echo OK || echo FAIL
ip netns exec eshield-client ping -c 20 -i 0.001 -W 2 10.0.0.1 >/dev/null 2>&1
echo "--- post-flood ping (expect FAIL):"; ip netns exec eshield-client ping -c 2 -W 2 10.0.0.1 >/dev/null 2>&1 && echo OK || echo FAIL

for i in $(seq 1 12); do
  sleep 2
  N=$(ip netns exec eshield-server curl -s -H "Authorization: Bearer hub-token" "http://10.0.0.1:9930/api/v1/policies?since=0&limit=100" | jq '.policies | length')
  echo "t+$((i*2))s hub policies: $N"
  [ "$N" != "0" ] && break
done
ip netns exec eshield-server curl -s -H "Authorization: Bearer hub-token" "http://10.0.0.1:9930/api/v1/policies?since=0&limit=100" | jq .
echo "=== node log (hub/blacklist lines) ==="
grep -iE "hub|blacklist|push|sync" /tmp/h3-node.log | tail -30
