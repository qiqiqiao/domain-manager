#!/usr/bin/env bash
set -euo pipefail

# Build frontend and static Linux binaries without requiring make.
# Requirements: Go 1.24+, Node.js 20+, npm.
# Usage: ./scripts/build-release.sh

cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
COMMIT="${COMMIT:-$(git rev-parse --short HEAD 2>/dev/null || echo dev)}"
BUILD_TIME="${BUILD_TIME:-$(date -u +%Y-%m-%dT%H:%M:%SZ)}"
LDFLAGS="-s -w -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.buildTime=${BUILD_TIME}"

echo "==> Building frontend"
cd frontend
if [[ -f package-lock.json ]]; then
  npm ci --no-audit --no-fund
else
  npm install --no-audit --no-fund
fi
npm run build
cd ..

mkdir -p dist

echo "==> Building linux/amd64"
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$LDFLAGS" \
  -o dist/domain-manager-linux-amd64 ./cmd/server

echo "==> Building linux/arm64"
CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$LDFLAGS" \
  -o dist/domain-manager-linux-arm64 ./cmd/server

cd dist
sha256sum domain-manager-linux-amd64 domain-manager-linux-arm64 > checksums.txt
chmod +x domain-manager-linux-amd64 domain-manager-linux-arm64

echo "==> Done"
ls -lh
cat checksums.txt
