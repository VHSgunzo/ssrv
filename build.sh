#!/usr/bin/env bash
set -o pipefail

# WITH_UPX=1
# VERSION=0.0.1
# ARCHS=(i386 x86_64 armv7 aarch64 source)

SRC_DIR="$(dirname "$(realpath "$BASH_SOURCE")")"

if [ ! -n "$ARCHS" ]
    then
        [ -n "$1" ] && \
        ARCHS=("$@")||\
        ARCHS="$(uname -m)"
fi
[ "$ARCHS" == 'all' ] && \
ARCHS=(i386 x86_64 armv7 aarch64 source)

GIT_VERSION="$(git describe --long --tags 2>/dev/null|sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g')"
[ -n "$GIT_VERSION" ] && \
VERSION="$GIT_VERSION"||\
VERSION="${VERSION:-HEAD}"

cd "$SRC_DIR"

export CGO_ENABLED=0
for ARCH in "${ARCHS[@]}"
    do
        mkdir -p "build/$ARCH"

        case "$ARCH" in
            source)
                git clean -fdx -e build
                go mod vendor
                tar --zst --exclude build -cf \
                    "build/$ARCH/shellsrv.tar.zst" -C "$SRC_DIR" .
                exit ;;
            i386|i686) GOARCH='386' ;;
            x86_64) GOARCH='amd64' ;;
            armv7) GOARCH='arm' ;;
            aarch64) GOARCH='arm64' ;;
            *) GOARCH="$ARCH" ;;
        esac
        export GOARCH

        go build -ldflags "-X main.VERSION=$VERSION -s -w" \
            -o "build/$ARCH/shellsrv"

        if [ "$WITH_UPX" == 1 ] && command -v upx &>/dev/null
            then upx --force-overwrite -9 --best \
                "build/$ARCH/shellsrv" -o "build/$ARCH/shellsrv-upx"
        fi
done
