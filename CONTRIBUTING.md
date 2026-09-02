# Contributing to Enodia

## Before your first pull request

You will be asked to sign the [CLA](CLA.md). The CLA Assistant bot posts a link
on your pull request; signing takes one click. This is required because Enodia
is dual licensed — see the CLA for the reasoning. You keep the copyright to
your work.

## Adding support for a product

This is the most useful contribution and the one with the clearest recipe.

**One product, one file.** `internal/probe/<product>.go`. Do not add a product
to an existing file even when the transport is identical — the exception is a
vendor family that genuinely shares one endpoint, which is parameterised in the
registry rather than copy-pasted.

**Register it explicitly** in `internal/probe/registry.go`. There is no
`init()` self-registration: the registry is meant to read as a table of
contents, and a pull request that adds a product should show up as a diff there.

**Record a real response** in `internal/probe/testdata/`, named
`<product>_<version>.<ext>` — for example `jira_10.3.2.xml`. Capture it from an
actual instance. Strip hostnames, tokens, and anything internal.

**A probe without testdata will not be merged.** Tests run offline against
these files; they are what stops a refactor from silently breaking twenty
probes, and they document what the vendor actually returns.

### Checklist

- [ ] `Meta()` declares the product, the default lifecycle resolver, and the
      auth requirements
- [ ] Transport lives in the probe. HTTP probes use the `FetchHTTP` helper
- [ ] `context.Context` is threaded through every call that touches the network
- [ ] Errors are wrapped with a typed sentinel (`ErrUnreachable`, `ErrAuth`,
      `ErrNotSupported`, `ErrUnparseable`) — never a bare string
- [ ] Version returned raw; normalisation is the engine's job
- [ ] Recorded response in `testdata/`, with a test that parses it
- [ ] No retry logic inside the probe — the runner owns that
- [ ] Product listed in the README table if it is a notable addition

### What a probe must not do

- Log, print, or return credentials — including partially masked ones
- Retry, sleep, or implement its own timeout
- Read configuration files or environment variables directly
- Mutate anything on the target. Probes are strictly read-only, and should
  prefer endpoints that work unauthenticated where the vendor offers one

## Config schema changes

The config and the inventory format are versioned. Anything that changes their
shape needs a `schemaVersion` bump and a note in the changelog. Users pin this
tool in CI; silently changing what their config means is not acceptable.

## Code style

`gofmt` and `golangci-lint run` must be clean. Beyond that, ordinary Go —
prefer boring, explicit code over clever code. This is a tool that holds
production credentials; readability is a security property.

## Commits

Conventional Commits, so the changelog can be generated:

```
feat(probe): add Nextcloud support
fix(tls): honour SSL_CERT_FILE on Linux
docs: clarify air-gapped workflow
```

## Reporting a broken probe

Vendors change their APIs. If a probe stops parsing, that is a bug in Enodia,
not in your setup. Open an issue with the product, its version, and the raw
response body — with hostnames and tokens removed.

As a stopgap you can always fall back to `product: generic` with a hand-written
parser spec while a fix ships.
