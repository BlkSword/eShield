#!/bin/bash
# eShield 卸载脚本
set -e

echo "停止并禁用 eShield 服务..."
systemctl stop eshield 2>/dev/null || true
systemctl disable eshield 2>/dev/null || true

echo "移除 systemd 服务..."
rm -f /etc/systemd/system/eshield.service
systemctl daemon-reload

echo "移除二进制..."
rm -f /usr/local/bin/eshield

echo "是否删除配置文件 /etc/eshield？（y/N）"
read -r answer
if [ "$answer" = "y" ] || [ "$answer" = "Y" ]; then
    rm -rf /etc/eshield
fi

echo "✓ eShield 已卸载"
