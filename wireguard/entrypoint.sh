#!/bin/bash
set -e

CONFIG_FILE="/config/wg0.conf"

# 检查宿主机是否支持 WireGuard
if ! modprobe wireguard &>/dev/null; then
  echo "错误: 宿主机内核不支持 WireGuard"
  exit 1
fi

# 检查配置文件
if [ ! -f "$CONFIG_FILE" ]; then
  echo "错误: 找不到配置文件 $CONFIG_FILE"
  exit 1
fi

echo "加载 WireGuard 配置: $CONFIG_FILE"
wg-quick up "$CONFIG_FILE"

# 捕获 SIGTERM/SIGINT 信号，优雅关闭
trap 'echo "停止 WireGuard..."; wg-quick down "$CONFIG_FILE"; exit 0' SIGTERM SIGINT

# 保持容器前台运行
tail -f /dev/null
