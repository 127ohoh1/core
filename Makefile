GO ?= go

.PHONY: all fmt fmt-check vet test race fuzz vuln staticcheck bench bench-idle build dist up down test-redis faults

all: fmt-check vet race

fmt:
	gofmt -w .

fmt-check:
	@test -z "$$(gofmt -l .)" || (gofmt -l . && echo "gofmt needed" && exit 1)

vet:
	$(GO) vet ./...

test:
	$(GO) test ./...

race:
	$(GO) test -race -count=1 ./...

fuzz:
	@for p in $$($(GO) list ./... ); do \
	  for f in $$($(GO) test $$p -list '^Fuzz' | grep '^Fuzz'); do \
	    $(GO) test $$p -run '^$$' -fuzz "^$$f$$" -fuzztime 10s || exit 1; \
	  done; \
	done

vuln:
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest ./...

bench:
	$(GO) test -run '^$$' -bench . -benchmem ./protocol/... ./dataplane/... 
	$(GO) test -run '^$$' -bench 'DirectBaseline|ProxySmallRequest|ProxyBulk1MiB' -benchtime 2s -count 3 ./benchmarks

# Idle tunnels: N authenticated, registered tunnels held open (both ends in one process).
bench-idle:
	OHOH_BENCH_IDLE=$${N:-2000} $(GO) test -run TestIdleTunnels -v -count=1 -timeout 30m ./benchmarks

staticcheck:
	$(GO) run honnef.co/go/tools/cmd/staticcheck@latest ./...

# Redis directory contract against a real Redis (needs docker).
test-redis:
	docker rm -f ohoh-test-redis >/dev/null 2>&1 || true
	docker run -d --rm --name ohoh-test-redis -p 127.0.0.1:26379:6379 redis:7-alpine >/dev/null
	@sleep 1
	OHOH_TEST_REDIS=127.0.0.1:26379 $(GO) test -race -count=1 -v -run 'DirectoryContract' ./dataplane/routing; s=$$?; docker rm -f ohoh-test-redis >/dev/null; exit $$s

# Fault injection against the running Compose stack (start it first: make up).
faults:
	tests/failure/compose-faults.sh

build:
	$(GO) build -o bin/ ./cmd/...

# Release artifacts: cross-compiled CLI + checksums + module build info.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
LDFLAGS := -s -w -X github.com/127ohoh1/core/client/cli.Version=$(VERSION)
dist:
	rm -rf dist && mkdir -p dist
	for t in linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64; do \
	  os=$${t%/*}; arch=$${t#*/}; ext=""; [ $$os = windows ] && ext=".exe"; \
	  CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -trimpath -ldflags "$(LDFLAGS)" -o dist/127ohoh1_$(VERSION)_$${os}_$${arch}$$ext ./cmd/127ohoh1 || exit 1; \
	done
	cd dist && (sha256sum * > SHA256SUMS)
	$(GO) version -m dist/127ohoh1_$(VERSION)_linux_amd64 > dist/BUILDINFO.txt 2>/dev/null || true

up:
	@mkdir -p .devtls
	OHOH_UID=$$(id -u) OHOH_GID=$$(id -g) docker compose -f deploy/docker/compose.yaml up --build

down:
	OHOH_UID=$$(id -u) OHOH_GID=$$(id -g) docker compose -f deploy/docker/compose.yaml down -v
