# eShield 部署指南

## 系统要求

- Linux 内核 >= 5.10，启用 BTF：
  ```bash
  ls /sys/kernel/btf/vmlinux
  ```
-  root 或以下 capability：
  - `CAP_BPF`
  - `CAP_NET_ADMIN`
  - `CAP_NET_RAW`
  - `CAP_PERFMON`
  - `CAP_IPC_LOCK`

## 一键安装

```bash
curl -fsSL https://raw.githubusercontent.com/BlkSword/eShield/main/scripts/install.sh | sudo bash
```

或从源码构建安装（推荐用于 aarch64 或离线环境）：

```bash
sudo bash scripts/install.sh --build
```

安装脚本会：构建/下载二进制 → 校验 ELF 与 SHA256SUMS → 安装到 `/usr/local/bin/eshield` →
创建 `/etc/eshield/config.toml`（网卡按实际活动网卡写入）→ 安装并启动 systemd 服务。

## 手动部署

### 1. 下载静态二进制

```bash
VERSION=0.4.7
curl -fsSLO "https://github.com/BlkSword/eShield/releases/download/v${VERSION}/eshield-x86_64-unknown-linux-musl"
sudo install -m 755 eshield-x86_64-unknown-linux-musl /usr/local/bin/eshield
```

### 2. 创建配置

```bash
sudo mkdir -p /etc/eshield
sudo curl -fsSL -o /etc/eshield/config.toml \
  https://raw.githubusercontent.com/BlkSword/eShield/v0.4.7/packaging/config.example.toml
sudoedit /etc/eshield/config.toml
```

### 3. 安装 systemd 服务

```bash
sudo curl -fsSL -o /lib/systemd/system/eshield.service \
  https://raw.githubusercontent.com/BlkSword/eShield/v0.4.7/packaging/eshield.service
sudo systemctl daemon-reload
sudo systemctl enable --now eshield
```

### 4. 查看状态

```bash
sudo systemctl status eshield
sudo eshield status
```

## 容器部署

```bash
docker run -d --name eshield \
  --cap-add BPF --cap-add NET_ADMIN --cap-add NET_RAW \
  --cap-add PERFMON --cap-add IPC_LOCK \
  -v /etc/eshield/config.toml:/etc/eshield/config.toml:ro \
  -p 8720:8720 \
  ghcr.io/blksword/eshield:v0.4.7
```

> 容器内需要能访问宿主网卡才能挂载 XDP，通常使用 `--network host` 并显式指定 `ESHIELD_XDP_MODE=skb`。

## Kubernetes DaemonSet

`packaging/k8s/` 提供可直接套用的清单：

| 文件 | 作用 |
|---|---|
| `namespace.yaml` | 独立命名空间 |
| `configmap.yaml` | 基础配置（网卡、Token、白名单） |
| `daemonset.yaml` | 每节点一份，`hostNetwork: true` + `hostPID: true`，挂载 `/sys` 与 BTF |
| `service.yaml` | 暴露 8720 端口的 ClusterIP |

```bash
kubectl apply -f packaging/k8s/
```

## 分布式 Hub 部署

多节点场景下，可独立部署 `eshield-hub` 作为策略聚合中心（v0.4.2 起，v0.4.6 起支持每节点 Token，v0.4.7 起 Hub 内置 TLS/mTLS）。

### 下载并启动 Hub

```bash
VERSION=0.4.7
curl -fsSLO "https://github.com/BlkSword/eShield/releases/download/v${VERSION}/eshield-hub-x86_64-unknown-linux-gnu"
sudo install -m 755 eshield-hub-x86_64-unknown-linux-gnu /usr/local/bin/eshield-hub

sudo mkdir -p /var/lib/eshield-hub
sudo eshield-hub --bind 0.0.0.0:9930 --token "your-hub-token"
```

TLS 有两种方式，二者选其一：

1. **Hub 内置 TLS（推荐，v0.4.7+）**：`--tls-cert /etc/eshield-hub/server.pem --tls-key /etc/eshield-hub/server.key`，
   可选 `--tls-client-ca ca.pem` 开启 mTLS，要求节点持有客户端证书。
2. **反代终结 TLS**：在 Hub 前挂 nginx/Caddy，节点配置 `urls = ["https://hub.example.com:9930"]`。

> 多节点部署建议使用 `--node-tokens-file /etc/eshield-hub/node-tokens`，文件每行 `node_name:token`。节点专属 Token 认证成功后，Hub 会强制以认证节点名记录/限流，避免请求体伪造 node_name；master token 仍兼容旧部署，但无法阻止伪造节点名。


### 节点接入 Hub

编辑 `/etc/eshield/config.toml`：

```toml
[hub]
enabled = true
urls = ["https://hub.example.com:9930"]
node_name = "web-tier-01"
token = "your-hub-token"
sync_pull_interval_s = 10
sync_push_interval_s = 5
sync_rules_enabled = true
sync_rules_interval_s = 30
```

重载节点：

```bash
sudo systemctl reload eshield
```

### systemd 服务示例（Hub）

```ini
# /lib/systemd/system/eshield-hub.service
[Unit]
Description=eShield Distributed Policy Hub
After=network.target

[Service]
Type=simple
ExecStart=/usr/local/bin/eshield-hub --bind 0.0.0.0:9930 --token "your-hub-token"
Restart=on-failure
RestartSec=5

[Install]
WantedBy=multi-user.target
```

## 升级

```bash
sudo systemctl stop eshield
# 替换二进制
sudo systemctl start eshield
```

配置文件与动态规则库默认位于 `/var/lib/eshield/rules.redb`（Hub 为 `/var/lib/eshield-hub/policies.redb`），升级后自动恢复。
