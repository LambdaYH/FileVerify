#!/bin/sh
set -eu
cd "$(dirname "$0")"
export GOOS=linux
export GOARCH="${GOARCH:-amd64}"
export CGO_ENABLED=0
GOARCH="$(go env GOHOSTARCH)" go test ./...
go build -trimpath -ldflags="-s -w" -o "FolderVerify-linux-$GOARCH" .
printf 'Built FolderVerify-linux-%s\n' "$GOARCH"
