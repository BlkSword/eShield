#!/bin/bash
# eShield 完整攻防测试脚本
# 在单台机器上用 network namespace + veth 模拟攻防两端
set -e

PACKETS="${PACKETS:-100000}"
DURATION="${DURATION:-5}"
SERVER_NS="eshield-server"
CLIENT_NS="eshield-client"
SERVER_IP="10.0.0.1"
CLIENT_IP="10.0.0.2"
ESHIELD_BIN="${ESHIELD_BIN:-./target/x86_64-unknown-linux-musl/release/eshield}"

if [ "$EUID" -ne 0 ]; then
    echo "请使用 sudo 运行"
    exit 1
fi

cleanup() {
    echo "[cleanup] 清理 netns 和后台进程..."
    kill $HTTP_PID $ESHIELD_PID 2>/dev/null || true
    wait $HTTP_PID 2>/dev/null || true
    wait $ESHIELD_PID 2>/dev/null || true
    ip netns del "$SERVER_NS" 2>/dev/null || true
    ip netns del "$CLIENT_NS" 2>/dev/null || true
    rm -f /tmp/eshield-attack-test.toml /tmp/eshield-attack-test.redb
}
trap cleanup EXIT

echo "=== eShield 完整攻防测试 ==="
echo "日期: $(date)"
echo ""

# 1. 创建 netns 和 veth
ip netns add "$SERVER_NS"
ip netns add "$CLIENT_NS"
ip link add veth-server type veth peer name veth-client
ip link set veth-server netns "$SERVER_NS"
ip link set veth-client netns "$CLIENT_NS"

ip netns exec "$SERVER_NS" ip addr add "$SERVER_IP/24" dev veth-server
ip netns exec "$CLIENT_NS" ip addr add "$CLIENT_IP/24" dev veth-client
ip netns exec "$SERVER_NS" ip link set veth-server up
ip netns exec "$CLIENT_NS" ip link set veth-client up
ip netns exec "$SERVER_NS" ip link set lo up
ip netns exec "$CLIENT_NS" ip link set lo up

# 确保没有旧持久化规则影响测试
rm -f /tmp/eshield-attack-test.redb

# 2. 生成 eShield 配置
cat > /tmp/eshield-attack-test.toml <<EOF
interface = "veth-server"
web_bind = "0.0.0.0:8443"
log_level = "info"
log_json = false
store_path = "/tmp/eshield-attack-test.redb"

whitelist = ["${SERVER_IP}/32", "127.0.0.1/32"]
blacklist = []

udp_flood_enabled = true
icmp_flood_enabled = true
tcp_reset_on_drop = true

[rate_limit]
enabled = false            # 关闭速率限制，避免它抢在 Flood 模块之前丢弃
threshold = 10000          # SYN/UDP/ICMP Flood 模块共享该阈值；基线压测不应触发

[adaptive]
enabled = false
EOF

# 3. 在防御端启动一个支持并发的轻量 HTTP 服务（用于对比允许流量）
ip netns exec "$SERVER_NS" python3 - <<'PY' >/tmp/eshield-http-server.log 2>&1 &
import socketserver, http.server, sys
class Handler(http.server.SimpleHTTPRequestHandler):
    def log_message(self, fmt, *args):
        pass
with socketserver.ThreadingTCPServer(("10.0.0.1", 80), Handler) as httpd:
    httpd.serve_forever()
PY
HTTP_PID=$!
sleep 1

# 4. 启动 eShield
ip netns exec "$SERVER_NS" "$ESHIELD_BIN" start --config /tmp/eshield-attack-test.toml >/tmp/eshield-attack-test.log 2>&1 &
ESHIELD_PID=$!

# 等待就绪
for i in {1..30}; do
    if ip netns exec "$SERVER_NS" curl -fs "http://${SERVER_IP}:8443/ready" >/dev/null 2>&1; then
        echo "[ready] eShield 已启动"
        break
    fi
    sleep 0.5
done

api_stats() {
    local raw code
    # 从 127.0.0.1 访问，利用本机回环地址跳过 token 认证
    raw=$(ip netns exec "$SERVER_NS" curl -sS "http://127.0.0.1:8443/api/stats" 2>&1)
    code=$?
    if [ $code -ne 0 ]; then
        echo "stats-err($code): $raw"
        return
    fi
    echo "$raw" | jq -c '{
        total_packets,
        total_dropped,
        total_passed,
        current_dps,
        blacklist_blocked,
        rate_limited,
        syn_flood_blocked,
        udp_flood_blocked,
        icmp_flood_blocked,
        l7_blocked,
        tcp_rst_sent,
        tcp_rst_fail,
        tcp_rst_attempt
    }' 2>/dev/null || echo "raw-stats: $raw"
}

echo "[runtime config]"
ip netns exec "$SERVER_NS" curl -s "http://127.0.0.1:8443/api/config" | jq -c '.rate_limit'
echo "[baseline] 初始状态: $(api_stats)"
echo ""

# 5. 正常 HTTP 基线测试
echo "--- 测试 1: 正常 HTTP 请求基线 (wrk -> /) ---"
ip netns exec "$CLIENT_NS" wrk -t2 -c50 -d${DURATION}s "http://${SERVER_IP}/" || true
sleep 2
echo "测试后状态: $(api_stats)"
echo ""

# 6. UDP Flood 测试
echo "--- 测试 2: UDP Flood (hping3 -> :53) ---"
timeout 3s ip netns exec "$CLIENT_NS" hping3 --flood --udp -p 53 "$SERVER_IP" >/dev/null 2>&1 || true
sleep 2
echo "测试后状态: $(api_stats)"
echo ""

# 7. ICMP Flood 测试
echo "--- 测试 3: ICMP Flood (hping3 -> icmp) ---"
timeout 3s ip netns exec "$CLIENT_NS" hping3 --flood --icmp "$SERVER_IP" >/dev/null 2>&1 || true
sleep 2
echo "测试后状态: $(api_stats)"
echo ""

# 8. SYN Flood + 速率限制测试（放最后，因为会触发黑名单）
echo "--- 测试 4: SYN Flood + 速率限制 (hping3 -> :80) ---"
timeout 3s ip netns exec "$CLIENT_NS" hping3 --flood -S -p 80 "$SERVER_IP" >/dev/null 2>&1 || true
sleep 2
echo "测试后状态: $(api_stats)"
echo ""

# 9. TOP 攻击源
echo "--- TOP 10 攻击源 ---"
ip netns exec "$SERVER_NS" curl -fs "http://127.0.0.1:8443/api/stats" 2>/dev/null | jq -r '.top_attackers[] | "\(.ip): \(.count)"' 2>/dev/null | head -10 || true

echo ""
echo "=== 测试完成 ==="
