SHELL := /bin/bash
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
BUILD_TIME ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.buildTime=$(BUILD_TIME)

.PHONY: all frontend build build-linux-amd64 build-linux-arm64 release test vet fmt clean run

all: build

frontend:
	@if [ ! -d frontend/node_modules ] || [ frontend/package-lock.json -nt frontend/node_modules/.package-lock.json ]; then \
		cd frontend && npm ci --no-audit --no-fund; \
	fi
	cd frontend && npm run build

build: frontend
	CGO_ENABLED=0 go build -trimpath -ldflags "$(LDFLAGS)" -o domain-manager ./cmd/server
	@echo "built: ./domain-manager"

build-linux-amd64: frontend
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/domain-manager-linux-amd64 ./cmd/server
	@echo "built: dist/domain-manager-linux-amd64"

build-linux-arm64: frontend
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/domain-manager-linux-arm64 ./cmd/server
	@echo "built: dist/domain-manager-linux-arm64"

release: frontend
	mkdir -p dist
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/domain-manager-linux-amd64 ./cmd/server
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags "$(LDFLAGS)" -o dist/domain-manager-linux-arm64 ./cmd/server
	cd dist && sha256sum domain-manager-linux-amd64 domain-manager-linux-arm64 > checksums.txt
	@echo "release artifacts:"
	@ls -lh dist

test:
	CGO_ENABLED=0 go test ./...

vet:
	go vet ./...

fmt:
	gofmt -w cmd internal web

run: build
	./domain-manager

clean:
	rm -f domain-manager
	rm -rf dist
	@echo "cleaned build artifacts (embedded web/dist is retained)"
