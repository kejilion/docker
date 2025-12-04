FROM alpine:latest AS builder
ARG NGINX_VERSION ZSTD_VERSION

RUN apk add --no-cache pcre-dev zlib-dev openssl-dev wget git build-base brotli-dev \
    libxml2-dev libxslt-dev curl-dev yajl-dev lmdb-dev geoip-dev lua-dev \
    automake autoconf libtool pkgconfig linux-headers pcre2-dev

WORKDIR /usr/src

# Download NGINX
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz \
    && tar -zxf nginx-${NGINX_VERSION}.tar.gz

# Clone Brotli module
RUN git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli

# Clone and build ModSecurity
RUN git clone --depth 1 https://github.com/owasp-modsecurity/ModSecurity \
    && cd ModSecurity \
    && git submodule init \
    && git submodule update \
    && ./build.sh \
    && ./configure \
    && make && make install \
    && cd ..

# Clone ModSecurity NGINX module
RUN git clone https://github.com/owasp-modsecurity/ModSecurity-nginx \
    && cd ModSecurity-nginx \
    # && git checkout ef64996 \
    && cd ..

# Download and build Zstandard
RUN wget https://github.com/facebook/zstd/releases/download/v${ZSTD_VERSION}/zstd-${ZSTD_VERSION}.tar.gz \
    && tar -xzf zstd-${ZSTD_VERSION}.tar.gz \
    && cd zstd-${ZSTD_VERSION} \
    && make clean \
    && CFLAGS="-fPIC" make && make install \
    && cd ..

# Clone Zstandard NGINX module
RUN git clone --depth=10 https://github.com/tokers/zstd-nginx-module.git

# Configure and build NGINX with modules
RUN cd nginx-${NGINX_VERSION} && \
    ./configure --with-compat \
                --add-dynamic-module=../ngx_brotli \
                --add-dynamic-module=../ModSecurity-nginx \
                --add-dynamic-module=../zstd-nginx-module && \
    make modules





FROM nginx:alpine
ARG NGINX_VERSION CORERULESET_VERSION

# 复制压缩模块和 ModSecurity
COPY --from=builder /usr/src/nginx-${NGINX_VERSION}/objs/*.so /etc/nginx/modules/
COPY --from=builder /usr/local/modsecurity/lib/* /usr/lib/

# 创建配置目录并下载必要文件
RUN mkdir -p /etc/nginx/modsec/plugins \
    && wget https://github.com/coreruleset/coreruleset/archive/v${CORERULESET_VERSION}.tar.gz \
    && tar -xzf v${CORERULESET_VERSION}.tar.gz --strip-components=1 -C /etc/nginx/modsec \
    && rm -f v${CORERULESET_VERSION}.tar.gz \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-before.conf \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/coreruleset/wordpress-rule-exclusions-plugin/master/plugins/wordpress-rule-exclusions-config.conf \
    && wget -P /etc/nginx/modsec/plugins https://raw.githubusercontent.com/kejilion/nginx/main/waf/ldnmp-before.conf \
    && cp /etc/nginx/modsec/crs-setup.conf.example /etc/nginx/modsec/crs-setup.conf \
    && echo 'SecAction "id:900110, phase:1, pass, setvar:tx.inbound_anomaly_score_threshold=30, setvar:tx.outbound_anomaly_score_threshold=16"' >> /etc/nginx/modsec/crs-setup.conf \
    && wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/modsecurity.conf-recommended -O /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecRuleEngine DetectionOnly/SecRuleEngine On/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimit [0-9]\+/SecPcreMatchLimit 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/SecPcreMatchLimitRecursion [0-9]\+/SecPcreMatchLimitRecursion 20000/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyLimit\s\+[0-9]\+/SecRequestBodyLimit 52428800/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecRequestBodyNoFilesLimit\s\+[0-9]\+/SecRequestBodyNoFilesLimit 524288/' /etc/nginx/modsec/modsecurity.conf \
    && sed -i 's/^SecAuditEngine RelevantOnly/SecAuditEngine Off/' /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/crs-setup.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-config.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-before.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/rules/*.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && echo 'Include /etc/nginx/modsec/plugins/*-after.conf' >> /etc/nginx/modsec/modsecurity.conf \
    && apk add --no-cache lua5.1 lua5.1-dev pcre pcre-dev yajl yajl-dev \
    && ldconfig /usr/lib \
    && wget https://raw.githubusercontent.com/owasp-modsecurity/ModSecurity/v3/master/unicode.mapping -O /etc/nginx/modsec/unicode.mapping \
    && rm -rf /var/cache/apk/*
