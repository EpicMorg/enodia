GO ?= go
GOLANGCI_LINT ?= golangci-lint

.PHONY: all build vet test fmt fmt-check lint check tidy clean

all: check

build:
	$(GO) build ./...

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
