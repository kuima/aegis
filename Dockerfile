FROM alpine:3.23 AS build

WORKDIR /src
COPY . .
RUN apk add --no-cache --virtual .build-deps \
        build-base \
        cmake \
        boost-dev \
        openssl-dev \
    && cmake -S . -B /build -DENABLE_MYSQL=OFF \
    && cmake --build /build -j $(nproc) \
    && strip -s /build/trojan

FROM alpine:3.23

RUN apk add --no-cache \
        libstdc++ \
        boost-program_options \
        libssl3 \
        libcrypto3

COPY --from=build /build/trojan /usr/local/bin/trojan

WORKDIR /config
CMD ["trojan", "config.json"]
