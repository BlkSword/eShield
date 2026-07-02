#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="eshield-server"
CLIENT_NS="eshield-client"
SERVER_IP="10.0.0.1"
CLIENT_IP="10.0.0.2"

cleanup() {
    set +e
    pkill -f "eshield -c /tmp/eshield-debug.toml" 2>/dev/null || true
    pkill nginx 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
}
trap cleanup EXIT

# netns setup
ip netns add "$SERVER_NS" 2>/dev/null || true
ip netns add "$CLIENT_NS" 2>/dev/null || true
ip link add veth-server type veth peer name veth-client || true
ip link set veth-server netns "$SERVER_NS"
ip link set veth-client netns "$CLIENT_NS"
ip netns exec "$SERVER_NS" ip addr add "${SERVER_IP}/24" dev veth-server
ip netns exec "$CLIENT_NS" ip addr add "${CLIENT_IP}/24" dev veth-client
ip netns exec "$SERVER_NS" ip link set veth-server up
ip netns exec "$CLIENT_NS" ip link set veth-client up
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip link set lo up

# Python HTTP server
ip netns exec "$SERVER_NS" python3 - <<'PY' >/tmp/eshield-debug-http.log 2>&1 &
import socketserver, http.server
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
with socketserver.ThreadingTCPServer(("10.0.0.1", 80), Handler) as httpd:
    httpd.serve_forever()
PY
sleep 1

# eshield config
cat > /tmp/eshield-debug.toml <<EOF
interface = "veth-server"
web_bind = "0.0.0.0:8443"
log_level = "info"
ebpf_log_enabled = true
store_path = "/tmp/eshield-debug.redb"
whitelist = ["${SERVER_IP}/32", "127.0.0.1/32"]
blacklist = []
udp_flood_enabled = false
icmp_flood_enabled = false
tcp_reset_on_drop = false

[rate_limit]
enabled = false

[adaptive]
enabled = false
EOF
rm -f /tmp/eshield-debug.redb

ip netns exec "$SERVER_NS" /tmp/eshield-sync/target/x86_64-unknown-linux-musl/release/eshield start --config /tmp/eshield-debug.toml > /tmp/eshield-debug.log 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "--- single curl to / ---"
ip netns exec "$CLIENT_NS" curl -sS --connect-timeout 5 "http://${SERVER_IP}/" || true
echo ""
echo "--- stats ---"
ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/stats" | jq -c '{total_packets,total_dropped,total_passed,blacklist_blocked,rate_limited,syn_flood_blocked,udp_flood_blocked,icmp_flood_blocked,l7_blocked}' || true

echo "--- single curl to /admin ---"
ip netns exec "$CLIENT_NS" curl -sS --connect-timeout 5 "http://${SERVER_IP}/admin" || true
echo ""
echo "--- stats ---"
ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/stats" | jq -c '{total_packets,total_dropped,total_passed,blacklist_blocked,rate_limited,syn_flood_blocked,udp_flood_blocked,icmp_flood_blocked,l7_blocked}' || true

echo "--- log tail ---"
tail -n 40 /tmp/eshield-debug.log

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
