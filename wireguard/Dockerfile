FROM alpine:latest

LABEL maintainer="yourname@example.com"

# 安装必需工具
RUN apk add --no-cache \
    wireguard-tools \
    iproute2 \
    bash \
    curl \
    iptables \
    ip6tables \
    kmod

# 创建配置目录
RUN mkdir -p /config

# 设置工作目录
WORKDIR /config

# 拷贝启动脚本
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# 设置默认启动命令
ENTRYPOINT ["/entrypoint.sh"]
