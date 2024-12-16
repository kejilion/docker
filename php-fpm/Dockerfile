FROM php:fpm-alpine

RUN apk update && apk add --no-cache \
    imagemagick imagemagick-dev libgomp \
    git autoconf gcc g++ make pkgconfig \
    && curl -fsSL https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions \
    && chmod +x /usr/local/bin/install-php-extensions \
    && /usr/local/bin/install-php-extensions Imagick/imagick@65e27f2bc0 mysqli pdo_mysql gd intl zip exif bcmath opcache redis \
    && apk del git autoconf gcc g++ make pkgconfig \
    && rm -rf /var/cache/apk/*

RUN echo "upload_max_filesize=50M" > /usr/local/etc/php/conf.d/uploads.ini \
    && echo "post_max_size=50M" > /usr/local/etc/php/conf.d/post.ini \
    && echo "memory_limit=256M" > /usr/local/etc/php/conf.d/memory.ini \
    && echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini \
    && echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini \
    && echo "max_input_vars=3000" > /usr/local/etc/php/conf.d/max_input_vars.ini \
    && echo "max_input_vars=3000" > /usr/local/etc/php/conf.d/max_input_vars.ini \
    && cd /usr/local/etc/php/conf.d/ && curl -sL https://raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini \
    && cd /usr/local/etc/php-fpm.d/ && curl -sL https://raw.githubusercontent.com/kejilion/sh/main/www-1.conf  
