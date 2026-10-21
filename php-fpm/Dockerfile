FROM php:8.5-fpm-alpine3.23

# CVE-2026-109618 / CVE-2026-109619: never build on an unpatched PHP base.
RUN php -r 'if (PHP_VERSION_ID < 80512 || PHP_MAJOR_VERSION !== 8 || PHP_MINOR_VERSION !== 5) { fwrite(STDERR, "PHP 8.5.12 or newer in the 8.5 branch is required\n"); exit(1); }'

RUN apk update && apk add --no-cache \
    imagemagick imagemagick-dev libgomp \
    git autoconf gcc g++ make pkgconfig \
    && curl -fsSL https://github.com/mlocati/docker-php-extension-installer/releases/latest/download/install-php-extensions -o /usr/local/bin/install-php-extensions \
    && chmod +x /usr/local/bin/install-php-extensions \
    && /usr/local/bin/install-php-extensions imagick mysqli pdo_mysql gd intl zip exif bcmath opcache redis soap SourceGuardian \
    && apk del git autoconf gcc g++ make pkgconfig \
    && rm -rf /var/cache/apk/*

RUN curl -sS https://getcomposer.org/installer -o composer-setup.php \
    && php composer-setup.php --install-dir=/usr/local/bin --filename=composer \
    && rm composer-setup.php

RUN echo "upload_max_filesize=100M" > /usr/local/etc/php/conf.d/uploads.ini \
    && echo "post_max_size=100M" > /usr/local/etc/php/conf.d/post.ini \
    && echo "memory_limit=512M" > /usr/local/etc/php/conf.d/memory.ini \
    && echo "max_execution_time=1200" > /usr/local/etc/php/conf.d/max_execution_time.ini \
    && echo "max_input_time=600" > /usr/local/etc/php/conf.d/max_input_time.ini \
    && echo "max_input_vars=10000" > /usr/local/etc/php/conf.d/max_input_vars.ini \
    && curl -fsSL -o /usr/local/etc/php/conf.d/optimized_php.ini https://raw.githubusercontent.com/kejilion/sh/main/optimized_php.ini \
    && curl -fsSL -o /usr/local/etc/php-fpm.d/www.conf https://raw.githubusercontent.com/kejilion/sh/main/www-1.conf
