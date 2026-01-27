FROM php:8.4-fpm-alpine

RUN apk add --no-cache \
    postgresql-dev \
    libpq \
    docker-cli

RUN docker-php-ext-install pdo pdo_pgsql

WORKDIR /var/www
COPY . .