#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
VERSION="${VERSION:-}"
ALPINE_VERSION="${ALPINE_VERSION:-3.23}"
ENABLE_MYSQL="${ENABLE_MYSQL:-OFF}"
SIGN="${SIGN:-0}"
IMAGE="${IMAGE:-alpine:${ALPINE_VERSION}}"
PLATFORM="${PLATFORM:-linux/amd64}"

if [[ -z "$VERSION" ]]; then
    VERSION="$(sed -n 's/.*Version::version("\([^"]*\)").*/\1/p' "$ROOT_DIR/src/core/version.cpp" | head -n 1)"
fi

if [[ -z "$VERSION" ]]; then
    echo "VERSION is required and could not be read from src/core/version.cpp" >&2
    exit 1
fi

case "$ENABLE_MYSQL" in
    ON|OFF) ;;
    *)
        echo "ENABLE_MYSQL must be ON or OFF" >&2
        exit 1
        ;;
esac

if ! command -v docker >/dev/null 2>&1; then
    echo "docker is required" >&2
    exit 1
fi

DIST_DIR="$ROOT_DIR/dist"
PACKAGE_NAME="trojan-${VERSION}-linux-amd64"
PACKAGE_PATH="$DIST_DIR/${PACKAGE_NAME}.tar.xz"

mkdir -p "$DIST_DIR"
rm -rf "$DIST_DIR/trojan" "$PACKAGE_PATH" "$PACKAGE_PATH.sha224" "$PACKAGE_PATH.asc"

echo "Building ${PACKAGE_NAME} with ${IMAGE} on ${PLATFORM}"

docker run --rm --platform "$PLATFORM" \
    -e VERSION="$VERSION" \
    -e ENABLE_MYSQL="$ENABLE_MYSQL" \
    -v "$ROOT_DIR:/src" \
    -w /src \
    "$IMAGE" sh -euxc '
        apk update
        apk add --no-cache \
            build-base \
            cmake \
            boost-dev \
            boost1.84-static \
            openssl \
            openssl-dev \
            openssl-libs-static \
            xz \
            zlib-static

        if [ "$ENABLE_MYSQL" = "ON" ]; then
            apk add --no-cache mariadb-connector-c-dev
            MYSQL_CMAKE_FLAG="-DENABLE_MYSQL=ON"
        else
            MYSQL_CMAKE_FLAG="-DENABLE_MYSQL=OFF"
        fi

        cmake -S . -B /tmp/trojan-release-build \
            -DCMAKE_BUILD_TYPE=Release \
            $MYSQL_CMAKE_FLAG \
            -DBoost_USE_STATIC_LIBS=ON \
            -DOPENSSL_USE_STATIC_LIBS=TRUE \
            -DCMAKE_EXE_LINKER_FLAGS="-static -no-pie -static-libgcc -static-libstdc++"

        cmake --build /tmp/trojan-release-build -j "$(nproc)"
        strip -s /tmp/trojan-release-build/trojan

        rm -rf /src/dist/trojan
        mkdir -p /src/dist/trojan
        cp /tmp/trojan-release-build/trojan /src/dist/trojan/
        cp -r examples docs /src/dist/trojan/
        cp README.md LICENSE SECURITY.md CONTRIBUTORS.md CONTRIBUTING.md /src/dist/trojan/

        /src/dist/trojan/trojan -v
        tar -C /src/dist -cJf "/src/dist/trojan-${VERSION}-linux-amd64.tar.xz" trojan
        openssl dgst -sha224 "/src/dist/trojan-${VERSION}-linux-amd64.tar.xz" \
            > "/src/dist/trojan-${VERSION}-linux-amd64.tar.xz.sha224"
    '

if [[ "$SIGN" == "1" ]]; then
    if ! command -v gpg >/dev/null 2>&1; then
        echo "SIGN=1 requires gpg" >&2
        exit 1
    fi
    gpg --armor --detach-sign "$PACKAGE_PATH"
fi

echo
echo "Created:"
ls -lh "$PACKAGE_PATH" "$PACKAGE_PATH.sha224" 2>/dev/null
if [[ -f "$PACKAGE_PATH.asc" ]]; then
    ls -lh "$PACKAGE_PATH.asc"
fi
echo
cat "$PACKAGE_PATH.sha224"
