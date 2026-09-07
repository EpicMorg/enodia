GO ?= go
GOLANGCI_LINT ?= golangci-lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildCommit=$(COMMIT) -X main.buildDate=$(DATE)

WINDRES_AMD64 ?= x86_64-w64-mingw32-windres
WINDRES_386   ?= i686-w64-mingw32-windres

# Debian's mingw-w64 package ships no aarch64-w64-mingw32-windres at all —
# confirmed, it only has i686/x86_64 — so arm64 needs a different source:
# epicmorg/debian:trixie-develop carries llvm-mingw and sets $LLVM_MINGW_DIR
# to its version-stamped root (e.g. .../llvm-mingw/20260826). Inside that
# root, the *-ubuntu-22.04-x86_64 subdirectory is the one host bundle whose
# bin/ has cross windres for every target, arm64 included. The date in that
# subdirectory's own name changes with every toolchain refresh, hence the
# wildcard instead of hardcoding today's. Outside that image (LLVM_MINGW_DIR
# unset), this falls back to a bare command name that plain `command -v`
# will not find, and windows-resources skips it the same as any other
# missing cross-compiler.
LLVM_MINGW_HOST_DIR := $(firstword $(wildcard $(LLVM_MINGW_DIR)/llvm-mingw-*-ucrt-ubuntu-22.04-x86_64))
WINDRES_ARM64 ?= $(if $(LLVM_MINGW_HOST_DIR),$(LLVM_MINGW_HOST_DIR)/bin/aarch64-w64-mingw32-windres,aarch64-w64-mingw32-windres)

RES_SRC := build/windows
RES_PKG := cmd/enodia

# Best-effort FILEVERSION/PRODUCTVERSION quad from VERSION (e.g.
# "v1.2.3-4-gabc123" -> "1,2,3,0"). Anything that isn't vMAJOR.MINOR.PATCH
# (a bare "dev", a detached commit) falls back to 0,0,0,0 — the embedded
# resource is metadata, not something worth failing a build over.
VERSION_CSV := $(shell echo $(VERSION) | sed -n 's/^v\?\([0-9]\+\)\.\([0-9]\+\)\.\([0-9]\+\).*/\1,\2,\3,0/p')
VERSION_CSV := $(if $(VERSION_CSV),$(VERSION_CSV),0,0,0,0)

DIST_DIR     := dist
DIST_TARGETS := linux/amd64 linux/arm64 darwin/amd64 darwin/arm64 windows/amd64 windows/arm64 windows/386

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
# cmd/enodia/resource_windows_{amd64,386,arm64}.syso, so those builds carry
# a real icon and version info instead of the bare default. Go only links a
# .syso when it sits in the directory of the package being built, hence
# writing it straight into cmd/enodia rather than build/windows — it is
# generated, not committed (see .gitignore).
#
# windows/arm (32-bit ARM/"armv7") has no equivalent and never will: Go
# itself has no windows/arm build target at all (confirmed: `go tool dist
# list` doesn't list it, and building one fails with "unsupported GOOS/
# GOARCH pair") — there is no enodia binary of that shape to embed a
# resource into, regardless of what windres is available.
#
# Each architecture's windres is checked independently, and a missing one
# is a skip, not a failure: a future multiplatform build (see ROADMAP.md)
# covers plenty of targets that must not be blocked by one absent
# cross-compiler, and none of amd64/386/arm64 depend on each other.
windows-resources:
	sed -e 's/@VERSION_CSV@/$(VERSION_CSV)/g' -e 's/@VERSION_STR@/$(VERSION)/g' $(RES_SRC)/meta.rc.in > $(RES_SRC)/meta.rc
	@command -v $(WINDRES_AMD64) >/dev/null 2>&1 && (cd $(RES_SRC) && $(WINDRES_AMD64) -i meta.rc -O coff -o ../../$(RES_PKG)/resource_windows_amd64.syso) || echo "skip windows-resources (amd64): $(WINDRES_AMD64) not found (apt install mingw-w64)"
	@command -v $(WINDRES_386) >/dev/null 2>&1 && (cd $(RES_SRC) && $(WINDRES_386) -i meta.rc -O coff -o ../../$(RES_PKG)/resource_windows_386.syso) || echo "skip windows-resources (386): $(WINDRES_386) not found (apt install mingw-w64)"
	@command -v $(WINDRES_ARM64) >/dev/null 2>&1 && (cd $(RES_SRC) && $(WINDRES_ARM64) -i meta.rc -O coff -o ../../$(RES_PKG)/resource_windows_arm64.syso) || echo "skip windows-resources (arm64): $(WINDRES_ARM64) not found (needs llvm-mingw, e.g. epicmorg/debian:trixie-develop)"

windows-resources-clean:
	rm -f $(RES_SRC)/meta.rc $(RES_PKG)/resource_windows_amd64.syso $(RES_PKG)/resource_windows_386.syso $(RES_PKG)/resource_windows_arm64.syso

# Manual convenience for testing the Windows build locally, mirroring
# `make enodia`. Note the deliberate absence of -H=windowsgui: that flag
# hides the console window, which is right for a GUI app but would make a
# CLI tool's stdout/stderr invisible — enodia must keep the console
# subsystem.
windows-exe: windows-resources
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 $(GO) build -ldflags "$(LDFLAGS)" -o enodia_windows_amd64.exe ./cmd/enodia
	$(MAKE) windows-resources-clean

# Dev stopgap ahead of goreleaser (ROADMAP.md, "Then — packaging:
# multiplatform builds"): the same seven targets .goreleaser.yaml
# releases, built locally without needing a tag or CI. No CGO anywhere in
# this tree, so this is a plain GOOS/GOARCH matrix loop — nothing here
# should diverge from what goreleaser already does; if it needs to grow,
# grow that config instead. All three windows targets (amd64/386/arm64)
# get the icon/version resource via windows-resources, each independently
# — see that target's comment for what each one needs to be available.
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
