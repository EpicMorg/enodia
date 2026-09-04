GO ?= go
GOLANGCI_LINT ?= golangci-lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildCommit=$(COMMIT) -X main.buildDate=$(DATE)

WINDRES_AMD64 ?= x86_64-w64-mingw32-windres
RES_SRC       := build/windows
RES_PKG       := cmd/enodia

# Best-effort FILEVERSION/PRODUCTVERSION quad from VERSION (e.g.
# "v1.2.3-4-gabc123" -> "1,2,3,0"). Anything that isn't vMAJOR.MINOR.PATCH
# (a bare "dev", a detached commit) falls back to 0,0,0,0 — the embedded
# resource is metadata, not something worth failing a build over.
VERSION_CSV := $(shell echo $(VERSION) | sed -n 's/^v\?\([0-9]\+\)\.\([0-9]\+\)\.\([0-9]\+\).*/\1,\2,\3,0/p')
VERSION_CSV := $(if $(VERSION_CSV),$(VERSION_CSV),0,0,0,0)

DIST_DIR     := dist
DIST_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64

.PHONY: all build enodia windows-resources windows-resources-clean windows-exe dist vet test fmt fmt-check lint check tidy clean

all: check

build:
	$(GO) build ./...

# Produces a real ./enodia binary (build merely type-checks ./...) with
# version/commit/date baked in via -ldflags, the same variables goreleaser
# sets at release time (see .goreleaser.yaml).
enodia:
	$(GO) build -ldflags "$(LDFLAGS)" -o enodia ./cmd/enodia

# Compiles build/windows/{meta.rc.in,manifest.manifest,enodia.ico} into
# cmd/enodia/resource_windows_amd64.syso, so a windows/amd64 build carries
# a real icon and version info instead of the bare default. Go only links a
# .syso when it sits in the directory of the package being built, hence
# writing it straight into cmd/enodia rather than build/windows — it is
# generated, not committed (see .gitignore).
#
# windows/arm64 (also built by goreleaser) has no equivalent here: Debian's
# mingw-w64 package ships no aarch64-w64-mingw32-windres, only i686 and
# x86_64 — an ARM64 resource file would need llvm-mingw instead, not
# evaluated. That build stays icon-less until this is revisited.
#
# Missing windres is a skip, not a failure: a future multiplatform build
# (see ROADMAP.md) covers plenty of non-Windows targets that must not be
# blocked by an absent cross-compiler.
windows-resources:
	@command -v $(WINDRES_AMD64) >/dev/null 2>&1 || { echo "skip windows-resources: $(WINDRES_AMD64) not found (apt install mingw-w64)"; exit 0; }
	sed -e 's/@VERSION_CSV@/$(VERSION_CSV)/g' -e 's/@VERSION_STR@/$(VERSION)/g' $(RES_SRC)/meta.rc.in > $(RES_SRC)/meta.rc
	cd $(RES_SRC) && $(WINDRES_AMD64) -i meta.rc -O coff -o ../../$(RES_PKG)/resource_windows_amd64.syso

windows-resources-clean:
	rm -f $(RES_SRC)/meta.rc $(RES_PKG)/resource_windows_amd64.syso

# Manual convenience for testing the Windows build locally, mirroring
# `make enodia`. Note the deliberate absence of -H=windowsgui: that flag
# hides the console window, which is right for a GUI app but would make a
# CLI tool's stdout/stderr invisible — enodia must keep the console
# subsystem.
windows-exe: windows-resources
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o enodia_windows_amd64.exe ./cmd/enodia
	$(MAKE) windows-resources-clean

# Dev stopgap ahead of goreleaser (ROADMAP.md, "Then — packaging:
# multiplatform builds"): the same six targets .goreleaser.yaml releases,
# built locally without needing a tag or CI. No CGO anywhere in this tree,
# so this is a plain GOOS/GOARCH matrix loop — nothing here should diverge
# from what goreleaser already does; if it needs to grow, grow that config
# instead. windows/amd64 gets the icon/version resource via
# windows-resources; windows/arm64 does not (see that target's comment).
dist: windows-resources
	@mkdir -p $(DIST_DIR)
	@for t in $(DIST_TARGETS); do \
		os=$${t%/*}; arch=$${t#*/}; \
		ext=""; [ "$$os" = "windows" ] && ext=".exe"; \
		out=$(DIST_DIR)/enodia_$${os}_$${arch}$$ext; \
		echo "  GOOS=$$os GOARCH=$$arch -> $$out"; \
		CGO_ENABLED=0 GOOS=$$os GOARCH=$$arch $(GO) build -ldflags "$(LDFLAGS)" -o $$out ./cmd/enodia || exit 1; \
	done
	$(MAKE) windows-resources-clean

vet:
	$(GO) vet ./...

test:
	$(GO) test -race -cover ./...

fmt:
	gofmt -w .

fmt-check:
	@out="$$(gofmt -l .)"; \
	if [ -n "$$out" ]; then \
		echo "gofmt needs to be run on:"; \
		echo "$$out"; \
		exit 1; \
	fi

lint:
	$(GOLANGCI_LINT) run

tidy:
	$(GO) mod tidy

# The full set of checks CLAUDE.md requires before any change is done.
check: build vet fmt-check lint test

clean:
	$(GO) clean ./...
