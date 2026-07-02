#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="eshield-server"
CLIENT_NS="eshield-client"
SERVER_IP="10.0.0.1"
CLIENT_IP="10.0.0.2"

cleanup() {
    set +e
    [ -n "${ESHIELD_PID:-}" ] && kill $ESHIELD_PID 2>/dev/null || true
    [ -n "${HTTP_PID:-}" ] && kill $HTTP_PID 2>/dev/null || true
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

cat > /tmp/eshield-http-server.py <<'PY'
import socketserver, http.server
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
with socketserver.ThreadingTCPServer(("10.0.0.1", 80), Handler) as httpd:
    httpd.serve_forever()
PY
ip netns exec "$SERVER_NS" python3 /tmp/eshield-http-server.py >/tmp/eshield-http-server.log 2>&1 &
HTTP_PID=$!
sleep 1

CFG=/tmp/eshield-udp-only.toml
LOG=/tmp/eshield-udp-only.log
REDB=/tmp/eshield-udp-only.redb
rm -f "$CFG" "$LOG" "$REDB"
cat > "$CFG" <<EOF
interface = "veth-server"
web_bind = "0.0.0.0:8443"
log_level = "info"
store_path = "$REDB"
whitelist = ["${SERVER_IP}/32", "127.0.0.1/32"]
blacklist = []
udp_flood_enabled = true
icmp_flood_enabled = false
tcp_reset_on_drop = false

[rate_limit]
enabled = false
threshold = 100

[adaptive]
enabled = false

EOF

ip netns exec "$SERVER_NS" /tmp/eshield-sync/target/x86_64-unknown-linux-musl/release/eshield start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "--- before ---"
ip netns exec "$SERVER_NS" curl -sS --connect-timeout 3 "http://127.0.0.1:8443/api/stats" | jq -c '{total_dropped,udp_flood_blocked}' || true

echo "--- UDP flood 2s ---"
timeout 2s ip netns exec "$CLIENT_NS" hping3 --flood --udp -p 53 "$SERVER_IP" >/dev/null 2>&1 || true
sleep 2

echo "--- after ---"
ip netns exec "$SERVER_NS" curl -sS --connect-timeout 3 "http://127.0.0.1:8443/api/stats" | jq -c '{total_dropped,udp_flood_blocked,blacklist_blocked}' || true
