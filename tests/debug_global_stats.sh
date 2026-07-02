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

CFG=/tmp/eshield-gs.toml
LOG=/tmp/eshield-gs.log
REDB=/tmp/eshield-gs.redb
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
threshold = 10000

[adaptive]
enabled = false

EOF

ip netns exec "$SERVER_NS" /tmp/eshield-sync/target/x86_64-unknown-linux-musl/release/eshield start --config "$CFG" >"$LOG" 2>&1 &
ESHIELD_PID=$!
sleep 3

ip netns exec "$CLIENT_NS" curl -sS --connect-timeout 1 --max-time 1 "http://${SERVER_IP}/" -o /dev/null || true
sleep 2

echo "--- /api/stats ---"
ip netns exec "$SERVER_NS" curl -sS --connect-timeout 3 "http://127.0.0.1:8443/api/stats" | jq -c '{total_packets,total_dropped,total_passed,tcp_rst_sent,tcp_rst_fail}' || true

echo "--- bpftool map list ---"
MAP_ID=$(sudo bpftool net | grep veth-server | awk '{print $2}' | head -1)
echo "prog id: $MAP_ID"
sudo bpftool prog show id "$MAP_ID" 2>/dev/null | head -5 || true

# Find map id by name
BPF_MAP_ID=$(sudo bpftool map show name GLOBAL_STATS 2>/dev/null | head -1 | awk '{print $2}' | tr -d ':')
echo "GLOBAL_STATS map id: $BPF_MAP_ID"
if [ -n "$BPF_MAP_ID" ]; then
    sudo bpftool map dump id "$BPF_MAP_ID" 2>/dev/null | head -40 || true
fi
