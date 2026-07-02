#!/usr/bin/env bash
set -euo pipefail

SERVER_NS="eshield-server"
CLIENT_NS="eshield-client"
SERVER_IP="10.0.0.1"

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
ip netns exec "$CLIENT_NS" ip addr add "10.0.0.2/24" dev veth-client
ip netns exec "$SERVER_NS" ip link set veth-server up
ip netns exec "$CLIENT_NS" ip link set veth-client up
ip netns exec "$SERVER_NS" ip link set lo up

ip netns exec "$SERVER_NS" python3 - <<'PY' >/tmp/eshield-http-server.log 2>&1 &
import socketserver, http.server
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
with socketserver.ThreadingTCPServer(("10.0.0.1", 80), Handler) as httpd:
    httpd.serve_forever()
PY
HTTP_PID=$!
sleep 1

CFG=/tmp/eshield-rst-acl.toml
LOG=/tmp/eshield-rst-acl.log
REDB=/tmp/eshield-rst-acl.redb
rm -f "$CFG" "$LOG" "$REDB"
cat > "$CFG" <<EOF
interface = "veth-server"
web_bind = "0.0.0.0:8443"
log_level = "info"
store_path = "$REDB"
whitelist = ["${SERVER_IP}/32", "127.0.0.1/32"]
blacklist = []
udp_flood_enabled = false
icmp_flood_enabled = false
tcp_reset_on_drop = true

[rate_limit]
enabled = false

[adaptive]
enabled = false

[[port_acl]]
protocol = "tcp"
dport = "80"
action = "drop"
EOF

ip netns exec "$SERVER_NS" /tmp/eshield-sync/target/x86_64-unknown-linux-musl/release/eshield start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

echo "--- curl / with port ACL drop + RST ---"
time ip netns exec "$CLIENT_NS" curl -sS --connect-timeout 2 --max-time 2 "http://${SERVER_IP}/" -o /dev/null || true

echo "--- stats ---"
ip netns exec "$SERVER_NS" curl -sS --connect-timeout 3 "http://127.0.0.1:8443/api/stats" | jq -c '{total_packets,total_dropped,tcp_rst_sent,tcp_rst_fail,tcp_rst_attempt}' || true
