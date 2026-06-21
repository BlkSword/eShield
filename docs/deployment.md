# eShield 部署指南

## 环境要求

- Linux 内核 >= 5.10，且启用 BTF（`/sys/kernel/btf/vmlinux` 存在）
- root 权限或 `CAP_BPF`、`CAP_NET_ADMIN`、`CAP_NET_RAW`、`CAP_PERFMON`、`CAP_IPC_LOCK`

## 一键安装（从 Release）

```bash
curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo bash
```

或指定版本：

```bash
VERSION=0.1.0 curl -sSL https://raw.githubusercontent.com/eshield/eshield/main/scripts/install.sh | sudo VERSION=0.1.0 bash
```

## 从源码构建并安装

```bash
sudo bash scripts/install.sh --build
```

这会：

1. 使用 nightly 工具链编译 eBPF 程序
2. 使用 musl target 静态编译用户态二进制
3. 将 `eshield` 安装到 `/usr/local/bin`
4. 创建默认配置 `/etc/eshield/config.toml`
5. 安装并启用 systemd 服务

## 服务管理

```bash
# 查看状态
sudo systemctl status eshield

# 启动 / 停止 / 重启
sudo systemctl start eshield
sudo systemctl stop eshield
sudo systemctl restart eshield

# 热加载配置（发送 SIGHUP，不中断连接）
sudo systemctl reload eshield

# 查看日志
sudo journalctl -u eshield -f
```

## 卸载

```bash
sudo bash scripts/uninstall.sh
```

## 配置文件示例

```toml
interface = "eth0"
log_level = "info"
whitelist = ["127.0.0.1/32", "10.0.0.0/8"]
blacklist = ["192.0.2.1"]
web_port = 8443

[rate_limit]
enabled = true
threshold = 200
tick_ms = 100
decay_num = 7
decay_den = 8
block_duration_s = 300

[syn_proxy]
enabled = false

[l7_scan]
enabled = false
patterns = [
    { pattern = "ATTACKER" },
]
```
