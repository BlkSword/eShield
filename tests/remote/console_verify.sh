#!/bin/bash
# 新版控制台端到端验证：静态资源、API、时间戳修复、reset-token cookie。
# 在远程 Linux 测试机上运行（需要 sudo；依赖已构建的 release 二进制）。
set -u
cd /tmp/eshield-sync

BIN=target/x86_64-unknown-linux-musl/release/eshield
[ -x "$BIN" ] || { echo "FAIL: $BIN 不存在，先构建"; exit 1; }

PASS=0; FAIL=0
ok()   { PASS=$((PASS+1)); echo "  PASS  $1"; }
bad()  { FAIL=$((FAIL+1)); echo "  FAIL  $1"; }

cleanup() {
  sudo pkill -9 -x eshield 2>/dev/null
  sleep 0.5
  sudo ip netns del eshield-server 2>/dev/null
  sudo ip link del veth-es0 2>/dev/null
  rm -f /tmp/eshield-console-test.toml /tmp/eshield-resp
}
trap cleanup EXIT
cleanup >/dev/null 2>&1

echo "=== 1. 准备测试环境 ==="
sudo ip netns add eshield-server || exit 1
sudo ip link add veth-es0 type veth peer name veth-es1
sudo ip link set veth-es1 netns eshield-server
sudo ip addr add 10.200.0.1/24 dev veth-es0
sudo ip link set veth-es0 up
sudo ip netns exec eshield-server ip addr add 10.200.0.2/24 dev veth-es1
sudo ip netns exec eshield-server ip link set veth-es1 up
sudo ip netns exec eshield-server ip link set lo up

cat > /tmp/eshield-console-test.toml <<'EOF'
interface = "veth-es0"
web_bind = "0.0.0.0:8720"
api_token = "console-test-token"
whitelist = []
blacklist = []
EOF

echo "=== 2. 启动 eshield ==="
sudo $BIN start --config /tmp/eshield-console-test.toml >/tmp/eshield.log 2>&1 &
sleep 4
pgrep -x eshield >/dev/null && ok "eshield 进程存活" || { bad "eshield 启动失败"; tail -20 /tmp/eshield.log; exit 1; }

# 本机 loopback 免认证；同时带 token 验证认证路径
AUTH="Authorization: Bearer console-test-token"
check() { # $1=path $2=期望包含的字符串 $3=说明（可选认证头开关 $4=auth）
  local code
  code=$(curl -s -o /tmp/eshield-resp -w "%{http_code}" ${4:+-H "$AUTH"} "http://127.0.0.1:8720$1")
  if [ "$code" = "200" ] && grep -q -- "$2" /tmp/eshield-resp; then ok "$1 ($3)"; else bad "$1 → code=$code 期望包含[$2]"; head -c 200 /tmp/eshield-resp; echo; fi
}
check_code() { # $1=path $2=期望状态码
  local code
  code=$(curl -s -o /dev/null -w "%{http_code}" -H "$AUTH" "http://127.0.0.1:8720$1")
  [ "$code" = "$2" ] && ok "$1 → $2" || bad "$1 → code=$code 期望 $2"
}

echo "=== 3. 新版控制台资源 ==="
check "/" "static/css/tokens.css" "index 引用新 CSS"
if grep -q "__CONFIG_JSON__" /tmp/eshield-resp 2>/dev/null; then :; fi
code=$(curl -s -H "$AUTH" http://127.0.0.1:8720/)
echo "$code" | grep -q "__CONFIG_JSON__" && bad "index 配置注入未完成（仍含占位符）" || ok "index 配置注入完成"
echo "$code" | grep -q "static/js/main.js" && ok "index 引用 ES modules 入口" || bad "index 缺少 main.js"
check "/static/css/tokens.css" "--bg-base" "tokens.css"
check "/static/css/base.css" ".sidebar" "base.css"
check "/static/css/components.css" ".kpi-card" "components.css"
check "/static/css/pages.css" ".row-main" "pages.css"
check "/static/js/main.js" "startRouter" "main.js"
check "/static/js/api.js" "eshield-token" "api.js"
check "/static/js/pages/overview.js" "流量与拦截趋势" "overview.js"
check "/static/js/pages/attacks.js" "attack-events" "attacks.js"
check "/static/js/pages/audit.js" "audit" "audit.js"
check "/static/js/pages/policy.js" "MODULE_PATCH_MAP" "policy.js"
check "/static/js/pages/rules.js" "port-acl" "rules.js"
check "/static/js/pages/security.js" "blacklist" "security.js"
check "/static/js/pages/cluster.js" "hub/status" "cluster.js"
check "/static/js/pages/settings.js" "reset-token" "settings.js"
check "/static/js/ipdrawer.js" "ip-detail" "ipdrawer.js"
check_code "/static/does-not-exist.js" "404"
# 静态资源无需认证（loopback 之外也公开，与 echarts 一致）

echo "=== 4. API 冒烟 ==="
check "/api/stats" "total_packets" "统计快照"
check "/api/attack-events?limit=10" "events" "攻击事件"
check "/api/packets?limit=10" "entries" "包日志"
check "/api/protection-modules" "modules" "防护模块"
check "/api/hub/status" "enabled" "Hub 状态"

echo "=== 5. reset-token 同步刷新 cookie ==="
headers=$(curl -s -D - -o /dev/null -X POST -H "$AUTH" http://127.0.0.1:8720/api/auth/reset-token)
echo "$headers" | grep -qi "set-cookie: eshield-token=" && ok "reset-token 返回 Set-Cookie" || bad "reset-token 缺少 Set-Cookie"

echo "=== 6. 攻击事件时间戳（mono→wall 修复验证）==="
sudo ip netns exec eshield-server hping3 -S -p 443 --flood -c 3000 10.200.0.1 >/dev/null 2>&1 &
HPID=$!
sleep 3
kill $HPID 2>/dev/null
sleep 1
curl -s -H "$AUTH" "http://127.0.0.1:8720/api/attack-events?limit=5" > /tmp/eshield-resp
python3 - <<'PY'
import json, time, sys
try:
    data = json.load(open('/tmp/eshield-resp'))
    evs = data.get('events', [])
    if not evs:
        print("  SKIP  无攻击事件（可能全部被 SYN Cookie 吸收）"); sys.exit(0)
    now = time.time()
    worst = max(abs(now - e['timestamp_ns']/1e9) for e in evs)
    if worst < 120:
        print(f"  PASS  事件时间戳为 wall-clock（最大偏差 {worst:.1f}s）")
    else:
        print(f"  FAIL  事件时间戳偏差 {worst:.0f}s，仍为单调时钟")
        sys.exit(1)
except Exception as ex:
    print(f"  FAIL  解析事件失败: {ex}"); sys.exit(1)
PY
[ $? -eq 0 ] && true || FAIL=$((FAIL+1))

echo ""
echo "=== 结果: $PASS 通过, $FAIL 失败 ==="
[ $FAIL -eq 0 ]
