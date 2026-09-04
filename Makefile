GO ?= go
GOLANGCI_LINT ?= golangci-lint

VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  := $(shell git rev-parse --short HEAD 2>/dev/null || echo unknown)
DATE    := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
LDFLAGS := -X main.buildVersion=$(VERSION) -X main.buildCommit=$(COMMIT) -X main.buildDate=$(DATE)

.PHONY: all build enodia vet test fmt fmt-check lint check tidy clean

all: check

build:
	$(GO) build ./...

# Produces a real ./enodia binary (build merely type-checks ./...) with
# version/commit/date baked in via -ldflags, the same variables goreleaser
# sets at release time (see .goreleaser.yaml).
enodia:
	$(GO) build -ldflags "$(LDFLAGS)" -o enodia ./cmd/enodia

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
