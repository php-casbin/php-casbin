FROM php:7.1-cli-alpine3.10

WORKDIR /var/www

ARG PHP_EXTENSIONS="bcmath"
RUN apk --update add --no-cache $PHPIZE_DEPS bash && \
    docker-php-ext-install ${PHP_EXTENSIONS}

COPY --from=composer:latest /usr/bin/composer /usr/bin/composer