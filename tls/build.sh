#!/usr/bin/env bash
set -o pipefail

# WITH_UPX=1
# VERSION=0.0.1
# ARCHS=(source i386 x86_64 armv7 aarch64)
# CREATE_RELEASE_ARCHIVES=1

SRC_DIR="$(dirname "$BASH_SOURCE")"

if [ ! -n "$ARCHS" ]
    then
        [ -n "$1" ] && \
        ARCHS=("$@")||\
        ARCHS="$(uname -m)"
fi
[ "$ARCHS" == 'all' ] && \
ARCHS=(source i386 x86_64 armv7 aarch64)

GIT_VERSION="$(git describe --long --tags 2>/dev/null|sed 's/^v//;s/\([^-]*-g\)/r\1/;s/-/./g')"
[ -n "$GIT_VERSION" ] && \
VERSION="$GIT_VERSION"||\
VERSION="${VERSION:-HEAD}"
[ "$(basename "$(realpath "$SRC_DIR")")" == 'tls' ] && \
    VERSION="${VERSION}-tls"

cd "$SRC_DIR"

export CGO_ENABLED=0
for ARCH in "${ARCHS[@]}"
    do
        case "$ARCH" in
            source)
                echo "Create archive with source code..."
                git clean -fdx -e build
                go mod vendor
                tar -I 'zstd -T0 --ultra -22 --progress' --exclude build -l \
                --exclude tls --exclude .git --exclude .github --exclude .gitignore \
                -cf "$SRC_DIR/shellsrv-src-v${VERSION}.tar.zst" -C "$SRC_DIR" .
                continue ;;
            i386|i686) GOARCH='386' ;;
            x86_64) GOARCH='amd64' ;;
            armv7) GOARCH='arm' ;;
            aarch64) GOARCH='arm64' ;;
            *) GOARCH="$ARCH" ;;
        esac
        export GOARCH

        echo "Build for ${ARCH}..."
        mkdir -p "build/$ARCH"
        go build -trimpath -o "build/$ARCH/shellsrv" \
            -ldflags "-X main.VERSION=$VERSION -s -w -buildid="

        if [ "$WITH_UPX" == 1 ] && command -v upx &>/dev/null
            then
                echo "UPXing ${ARCH}..."
                upxdir="build/$ARCH/upx"
                mkdir -p "$upxdir"
                upx --force-overwrite -9 --best \
                "build/$ARCH/shellsrv" -o "$upxdir/shellsrv"
        fi

        if [ "$CREATE_RELEASE_ARCHIVES" == 1 ]
            then
                echo "Archiving release ${ARCH}..."
                tar -I 'zstd -T0 --ultra -22 --progress' -cf \
                "$SRC_DIR/shellsrv-${ARCH}-v${VERSION}.tar.zst" -C "build/$ARCH" .
        fi
done
