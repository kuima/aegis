ARG ALPINE_VERSION=3.23

FROM alpine:${ALPINE_VERSION} AS build

ARG ENABLE_MYSQL=OFF

WORKDIR /src
COPY . .
RUN apk upgrade --no-cache \
    && apk add --no-cache --virtual .build-deps \
        build-base \
        cmake \
        boost-dev \
        openssl-dev \
    && if [ "$ENABLE_MYSQL" = "ON" ]; then apk add --no-cache mariadb-connector-c-dev; fi \
    && cmake -S . -B /build -DENABLE_MYSQL="$ENABLE_MYSQL" \
    && cmake --build /build -j $(nproc) \
    && strip -s /build/trojan

FROM alpine:${ALPINE_VERSION}

ARG ENABLE_MYSQL=OFF

RUN apk upgrade --no-cache \
    && apk add --no-cache \
        libstdc++ \
        boost-program_options \
        libssl3 \
        libcrypto3 \
        ca-certificates \
    && if [ "$ENABLE_MYSQL" = "ON" ]; then apk add --no-cache mariadb-connector-c; fi

COPY --from=build /build/trojan /usr/local/bin/trojan

WORKDIR /config
CMD ["trojan", "config.json"]
