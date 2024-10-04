# 使用 PHP FPM Alpine 镜像
FROM php:fpm-alpine

# 设置环境变量
ENV GH_PROXY=

# 更新 APK 并安装必要的工具
RUN apk update && \
    apk add --no-cache \
        imagemagick \
        imagemagick-dev \
        git \
        autoconf \
        gcc \
        g++ \
        make \
        pkgconfig

# 安装 Imagick 扩展
RUN git clone ${GH_PROXY}https://github.com/Imagick/imagick /tmp/imagick && \
    cd /tmp/imagick && \
    phpize && \
    ./configure && \
    make && \
    make install && \
    echo 'extension=imagick.so' > /usr/local/etc/php/conf.d/imagick.ini && \
    rm -rf /tmp/imagick

# 下载并安装 PHP 扩展安装脚本
RUN curl -sL ${GH_PROXY}https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions && \
    chmod +x /usr/local/bin/install-php-extensions

# 安装所需的 PHP 扩展
RUN /usr/local/bin/install-php-extensions \
        mysqli \
        pdo_mysql \
        gd \
        intl \
        zip \
        exif \
        bcmath \
        opcache \
        redis

# 设置 PHP 配置
RUN echo "upload_max_filesize=50M" > /usr/local/etc/php/conf.d/uploads.ini && \
    echo "post_max_size=50M" > /usr/local/etc/php/conf.d/post.ini && \
    echo "memory_limit=256M" > /usr/local/etc/php/conf.d/memory.ini && \
    echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini && \
    echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini && \
    echo "max_input_vars=3000" > /usr/local/etc/php/conf.d/max_input_vars.ini

