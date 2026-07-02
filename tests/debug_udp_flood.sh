#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="eshield-server"
CLIENT_NS="eshield-client"
SERVER_IP="10.0.0.1"
CLIENT_IP="10.0.0.2"

cleanup() {
    set +e
    pkill -f "eshield start --config /tmp/eshield-udp.toml" 2>/dev/null || true
    pkill -f 'python3 - <<PY' 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add veth-server type veth peer name veth-client
ip link set veth-server netns "$SERVER_NS"
ip link set veth-client netns "$CLIENT_NS"
ip netns exec "$SERVER_NS" ip addr add "${SERVER_IP}/24" dev veth-server
ip netns exec "$CLIENT_NS" ip addr add "${CLIENT_IP}/24" dev veth-client
ip netns exec "$SERVER_NS" ip link set veth-server up
ip netns exec "$CLIENT_NS" ip link set veth-client up
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip link set lo up

ip netns exec "$SERVER_NS" python3 - <<'PY' >/tmp/eshield-udp-http.log 2>&1 &
import socketserver, http.server
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
with socketserver.ThreadingTCPServer(("10.0.0.1", 80), Handler) as httpd:
    httpd.serve_forever()
PY
sleep 1

cat > /tmp/eshield-udp.toml <<EOF
interface = "veth-server"
web_bind = "0.0.0.0:8443"
log_level = "info"
store_path = "/tmp/eshield-udp.redb"
whitelist = ["${SERVER_IP}/32", "127.0.0.1/32"]
blacklist = []
udp_flood_enabled = true
icmp_flood_enabled = false
tcp_reset_on_drop = true

[rate_limit]
enabled = false
threshold = 100

[adaptive]
enabled = false

EOF
rm -f /tmp/eshield-udp.redb

ip netns exec "$SERVER_NS" /tmp/eshield-sync/target/x86_64-unknown-linux-musl/release/eshield start --config /tmp/eshield-udp.toml >/tmp/eshield-udp.log 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "--- config ---"
ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/config" | jq -c '{udp_flood_enabled, icmp_flood_enabled, rate_limit_enabled, rate_limit: .rate_limit}' || true

echo "--- before ---"
ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/stats" | jq -c '{total_dropped, udp_flood_blocked, icmp_flood_blocked, blacklist_blocked}' || true

echo "--- UDP flood 3s ---"
timeout 3s ip netns exec "$CLIENT_NS" hping3 --flood --udp -p 53 "$SERVER_IP" >/dev/null 2>&1 || true
sleep 2

echo "--- after ---"
ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/stats" | jq -c '{total_dropped, udp_flood_blocked, icmp_flood_blocked, blacklist_blocked}' || true

kill $ESHIELD_PID 2>/dev/null || true
wait $ESHIELD_PID 2>/dev/null || true
