# Use the Alpine base image for the builder stage
FROM alpine:latest AS builder

# Install the necessary dependencies
RUN apk add --no-cache \
    pcre-dev \
    zlib-dev \
    openssl-dev \
    wget \
    git \
    build-base \
    brotli-dev

# Set the working directory
WORKDIR /app

# Set the Nginx version as a build argument
ARG NGINX_VERSION=1.27.2
# Download and extract the specified version of Nginx
RUN wget https://nginx.org/download/nginx-${NGINX_VERSION}.tar.gz && \
    tar -zxf nginx-${NGINX_VERSION}.tar.gz

# Clone the ngx_brotli module
RUN git clone --recurse-submodules -j8 https://github.com/google/ngx_brotli

# Build the dynamic modules
RUN cd nginx-${NGINX_VERSION} && \
    ./configure --with-compat --add-dynamic-module=../ngx_brotli && \
    make modules

# Use the official Nginx Alpine image for the final stage
FROM nginx:alpine

ARG NGINX_VERSION=1.27.2
# Copy the built modules from the builder stage
COPY --from=builder /app/nginx-${NGINX_VERSION}/objs/ngx_http_brotli_static_module.so /etc/nginx/modules/
COPY --from=builder /app/nginx-${NGINX_VERSION}/objs/ngx_http_brotli_filter_module.so /etc/nginx/modules/
