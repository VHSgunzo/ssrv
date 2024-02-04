#!/usr/bin/env bash

cd "$(dirname "$(realpath "$BASH_SOURCE")")"
CGO_ENABLED=1 go build -ldflags "-s -w" #&& \
# upx --force-overwrite -9 --best shellsrv -o shellsrv-upx
