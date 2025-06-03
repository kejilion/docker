FROM alpine:latest

ARG FRP_VERSION=0.61.0
ENV FRP_VERSION=${FRP_VERSION}

# 利用 Alpine 的 uname 判断实际运行时架构
RUN apk add --no-cache curl tar \
  && ARCH=$(case $(uname -m) in \
      x86_64) echo "amd64" ;; \
      aarch64) echo "arm64" ;; \
      armv7l) echo "arm" ;; \
      *) echo "unsupported" && exit 1 ;; \
    esac) \
  && curl -L https://github.com/fatedier/frp/releases/download/v${FRP_VERSION}/frp_${FRP_VERSION}_linux_${ARCH}.tar.gz -o frp.tar.gz \
  && tar -zxvf frp.tar.gz \
  && mv frp_${FRP_VERSION}_linux_${ARCH} /frp \
  && rm frp.tar.gz

WORKDIR /frp

CMD ["./frps", "-c", "frps.toml"]
