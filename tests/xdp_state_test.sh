#!/bin/bash
# XDP 挂载状态/模式回归（v0.4.8 新增）。
#
# 验证：
#   1) auto 模式能挂载，且 /api/stats 的 xdp_attached/xdp_mode 与内核实际状态一致
#   2) /ready 反映真实挂载状态（挂上时 200）
#   3) [xdp].mode = "native" 在驱动不支持时**报错退出**，而不是静默跑 SKB
#
# 用法：sudo SKIP_BUILD=1 bash tests/xdp_state_test.sh
set -e

if [ "$EUID" -ne 0 ]; then
    echo "Please run as root"
    exit 1
fi

if [ -z "${CARGO:-}" ]; then
    for c in "$(command -v cargo 2>/dev/null)" "$HOME/.cargo/bin/cargo" /root/.cargo/bin/cargo; do
        [ -x "$c" ] && CARGO="$c" && break
    done
fi
[ -n "${CARGO:-}" ] || { echo "FAIL: cargo not found"; exit 1; }
export PATH="$(dirname "$CARGO"):$PATH"
cd "$(dirname "$0")/.."

if [ -z "$SKIP_BUILD" ]; then
    "$CARGO" +"${ESHIELD_EBPF_TOOLCHAIN:-nightly-2026-07-31}" build --package eshield-ebpf \
        --target bpfel-unknown-none -Z build-std=core --release -q
    "$CARGO" build --package eshield --target x86_64-unknown-linux-musl --release -q
fi

NS_S=xd-server; NS_C=xd-client
PORT=18725; API="http://127.0.0.1:${PORT}"
FAILS=0
check() { if [ "$2" = "1" ]; then echo "[PASS] $3"; else echo "[FAIL] $3"; FAILS=$((FAILS+1)); fi; }

cleanup() {
    kill "$PID" 2>/dev/null || true
    wait "$PID" 2>/dev/null || true
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    rm -f /tmp/eshield-xd 2>/dev/null || true
}
trap cleanup EXIT

mkns() {
    ip netns del "$NS_C" 2>/dev/null || true
    ip netns del "$NS_S" 2>/dev/null || true
    ip netns add "$NS_S"; ip netns add "$NS_C"
    ip link add veth-x type veth peer name veth-y
    ip link set veth-x netns "$NS_S"; ip link set veth-y netns "$NS_C"
    ip -n "$NS_S" addr add 10.14.0.1/24 dev veth-x
    ip -n "$NS_C" addr add 10.14.0.2/24 dev veth-y
    ip -n "$NS_S" link set veth-x up; ip -n "$NS_C" link set veth-y up
    ip -n "$NS_S" link set lo up; ip -n "$NS_C" link set lo up
}

write_cfg() {
    cat > /tmp/eshield-xd.toml <<TOML
interface = "veth-x"
web_bind = "127.0.0.1:${PORT}"
log_level = "info"
store_path = "/tmp/eshield-xd.redb"
whitelist = ["127.0.0.1/32"]
blacklist = []

[xdp]
mode = "$1"
disable_offloads = true
auto_reattach = true

[rate_limit]
enabled = false
TOML
    rm -f /tmp/eshield-xd.redb
}

pkill -9 -f '^/tmp/eshield-xd( |$)' 2>/dev/null || true
mkns
cp target/x86_64-unknown-linux-musl/release/eshield /tmp/eshield-xd && chmod +x /tmp/eshield-xd

echo "=== 1) [xdp].mode = auto ==="
write_cfg auto
ip netns exec "$NS_S" /tmp/eshield-xd start --config /tmp/eshield-xd.toml >/tmp/xd_auto.log 2>&1 &
PID=$!
READY=0
for _ in $(seq 1 40); do
    if ip netns exec "$NS_S" curl -sf --max-time 2 "$API/ready" >/dev/null 2>&1; then READY=1; break; fi
    sleep 0.25
done
check "1" "$READY" "auto 模式启动并 /ready 200"
MODE=$(ip netns exec "$NS_S" curl -sS "$API/api/stats" | jq -r '.xdp_mode')
ATT=$(ip netns exec "$NS_S" curl -sS "$API/api/stats" | jq -r '.xdp_attached')
KERN=$(ip netns exec "$NS_S" ip -j link show dev veth-x | jq -r '.[0].xdp.prog.name // "none"')
check "1" "$([ "$ATT" = "true" ] && [ "$MODE" != "unknown" ] && echo 1 || echo 0)" \
      "/api/stats 反映真实状态（attached=$ATT mode=$MODE）"
check "1" "$([ "$KERN" = "eshield" ] && echo 1 || echo 0)" "内核里确实挂着 eshield（probe=$KERN）"
grep -q "attached XDP in" /tmp/xd_auto.log && echo "[PASS] 启动日志包含挂载模式" || {
    echo "[FAIL] 启动日志缺少挂载模式"; FAILS=$((FAILS+1)); }
kill "$PID" 2>/dev/null; wait "$PID" 2>/dev/null || true

echo
echo "=== 2) [xdp].mode = native（驱动不支持时必须显式失败）==="
mkns
write_cfg native
set +e
timeout 20 ip netns exec "$NS_S" /tmp/eshield-xd start --config /tmp/eshield-xd.toml >/tmp/xd_native.log 2>&1
NATIVE_RC=$?
set -e
grep -q "native XDP attach failed" /tmp/xd_native.log && HINT=1 || HINT=0
# veth 支持 native 时允许成功（rc=0 且出现 attached XDP in native）；
# 不支持时必须非零退出并给出 actionable 提示——绝不允许"静默跑 generic"。
if grep -q "attached XDP in native mode" /tmp/xd_native.log; then
    check "2" "1" "veth 支持 native，已挂载 native"
else
    check "2" "$([ "$NATIVE_RC" -ne 0 ] && [ "$HINT" = "1" ] && echo 1 || echo 0)" \
          "native 失败时显式退出并给出排障提示（rc=$NATIVE_RC）"
fi

echo
if [ "$FAILS" -ne 0 ]; then
    echo "=== 失败：$FAILS 项未通过 ==="
    exit 1
fi
echo "=== XDP 状态/模式测试全部通过 ==="
