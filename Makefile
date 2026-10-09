# PortTransit build automation.
#
# The targets that matter for a release are `make release`, which cross-compiles
# the relay and the client for the two architectures the installer script
# accepts, and `make checksums`, which produces the file the install script
# verifies. Everything else exists to make the local loop fast.
#
# Windows note: `make` is not shipped with Windows. Use scripts/build.ps1 there;
# it produces the same artifacts with the same linker flags.

SHELL := /bin/bash

MODULE     := porttransit
BINARY     := porttransit
CMD        := ./cmd/porttransit
DIST       := dist

VERSION    ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo 1.0.0)
COMMIT     ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo dev)
CHANNEL    ?= stable
BUILDTIME  ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# The version package's variables are the only thing the linker rewrites. Doing
# it here rather than in each command means a binary built by `make` and one
# built by CI report the same identity.
LDFLAGS := -s -w \
	-X '$(MODULE)/internal/version.Version=$(VERSION)' \
	-X '$(MODULE)/internal/version.Commit=$(COMMIT)' \
	-X '$(MODULE)/internal/version.BuildTime=$(BUILDTIME)' \
	-X '$(MODULE)/internal/version.Channel=$(CHANNEL)'

# The relay and the client are the same binary; only the configuration differs.
# Building one artifact keeps the deployment path simple: the client uploads
# itself, so the versions can never disagree.
TARGETS := linux/amd64 linux/arm64

.PHONY: all
all: build

.PHONY: help
help:
	@echo "PortTransit build targets:"
	@echo "  build        build the binary for the host platform"
	@echo "  release      cross-compile linux/amd64 and linux/arm64 into $(DIST)/"
	@echo "  tarballs     package the release binaries for the install script"
	@echo "  checksums    write $(DIST)/SHA256SUMS"
	@echo "  test         run the unit tests"
	@echo "  test-race    run the unit tests with the race detector"
	@echo "  vet          run go vet"
	@echo "  fmt          format the tree"
	@echo "  lint         run gofmt -l and go vet (what CI enforces)"
	@echo "  cover        write a coverage profile and print the total"
	@echo "  clean        remove build output"
	@echo "  install      install into $(DESTDIR)/usr/local/bin"
	@echo "  docker       build a container image (requires docker)"

.PHONY: build
build:
	go build -trimpath -ldflags "$(LDFLAGS)" -o $(BINARY) $(CMD)

.PHONY: release
release: clean
	@mkdir -p $(DIST)
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		echo "==> building $$os/$$arch"; \
		GOOS=$$os GOARCH=$$arch CGO_ENABLED=0 \
			go build -trimpath -ldflags "$(LDFLAGS)" \
			-o $(DIST)/$(BINARY)-$$os-$$arch $(CMD); \
	done
	@echo "==> artifacts in $(DIST)/"
	@ls -lh $(DIST)/

.PHONY: tarballs
tarballs: release
	@set -e; for t in $(TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		name=$(BINARY)-$(VERSION)-$$os-$$arch; \
		tmp=$$(mktemp -d); \
		cp $(DIST)/$(BINARY)-$$os-$$arch $$tmp/$(BINARY); \
		cp $(DIST)/$(BINARY)-$$os-$$arch $$tmp/$(BINARY)-$$os-$$arch; \
		cp scripts/install.sh $$tmp/install.sh; \
		cp README.md $$tmp/README.md; \
		tar -czf $(DIST)/$$name.tar.gz -C $$tmp .; \
		cp $(DIST)/$$name.tar.gz $(DIST)/$(BINARY)-$$os-$$arch.tar.gz; \
		rm -rf $$tmp; \
		echo "==> $(DIST)/$$name.tar.gz"; \
	done
	@echo "==> 同时生成了不带版本号的副本，供 install.sh 的 latest/download 使用"

.PHONY: checksums
checksums:
	@cd $(DIST) && sha256sum * > SHA256SUMS && cat SHA256SUMS

.PHONY: test
test:
	go test ./...

.PHONY: test-race
test-race:
	go test -race ./...

.PHONY: vet
vet:
	go vet ./...

.PHONY: fmt
fmt:
	gofmt -s -w .

.PHONY: lint
lint:
	@out=$$(gofmt -s -l . | grep -v '^vendor/' || true); \
	if [ -n "$$out" ]; then echo "these files are not gofmt'd:"; echo "$$out"; exit 1; fi
	go vet ./...

.PHONY: cover
cover:
	go test -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

.PHONY: clean
clean:
	rm -rf $(DIST) $(BINARY) $(BINARY).exe coverage.out

.PHONY: install
install: build
	install -D -m 0755 $(BINARY) $(DESTDIR)/usr/local/bin/$(BINARY)

.PHONY: docker
docker:
	docker build -t $(BINARY):$(VERSION) -f Dockerfile .
