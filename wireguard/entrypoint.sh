#!/bin/bash
set -e

CONFIG_FILE="/config/wg0.conf"

# 检查配置文件是否存在
if [ ! -f "$CONFIG_FILE" ]; then
  echo "错误: 未找到 $CONFIG_FILE"
  exit 1
fi

echo "加载 WireGuard 配置: $CONFIG_FILE"

# 启动 wg-quick
wg-quick up "$CONFIG_FILE"

# 捕获 SIGTERM 或 SIGINT，优雅退出
trap 'echo "停止 WireGuard..."; wg-quick down "$CONFIG_FILE"; exit 0' SIGTERM SIGINT

# 保持容器前台运行
tail -f /dev/null
