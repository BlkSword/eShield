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
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

## 手动部署

### 1. 下载静态二进制

```bash
VERSION=0.1.2
curl -LO "https://github.com/eshield/eshield/releases/download/v${VERSION}/eshield-x86_64-unknown-linux-musl"
sudo install -m 755 eshield-x86_64-unknown-linux-musl /usr/local/bin/eshield
```

### 2. 创建配置

```bash
sudo mkdir -p /etc/eshield
sudo curl -o /etc/eshield/config.toml \
  https://raw.githubusercontent.com/eshield/eshield/v0.1.2/packaging/config.example.toml
sudoedit /etc/eshield/config.toml
```

### 3. 安装 systemd 服务

```bash
sudo curl -o /lib/systemd/system/eshield.service \
  https://raw.githubusercontent.com/eshield/eshield/v0.1.2/packaging/eshield.service
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
  -p 8443:8443 \
  ghcr.io/eshield/eshield:v0.1.2
```

## Kubernetes DaemonSet

见 `packaging/k8s/`（TODO）。

## 升级

```bash
sudo systemctl stop eshield
# 替换二进制
sudo systemctl start eshield
```

配置文件与动态规则库默认位于 `/var/lib/eshield/rules.db`，升级后自动恢复。
