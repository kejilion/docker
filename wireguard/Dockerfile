FROM alpine:latest

# 更新并安装 WireGuard 工具
RUN apk add --no-cache wireguard-tools iproute2 bash curl

# 创建配置文件目录
RUN mkdir -p /config

# 设置工作目录
WORKDIR /config

# 启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 默认执行脚本
ENTRYPOINT ["/entrypoint.sh"]
