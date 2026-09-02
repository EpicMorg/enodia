# Enodia

Service inventory and lifecycle (EOL) monitoring. Go, single static binary,
AGPL-3.0-or-later with a CLA.

Read `@docs/DECISIONS.md` before proposing architectural changes. Those
decisions were argued through and settled; reopening one needs a reason, not a
preference.

## Build and test

```bash
go build ./...
go vet ./...
go test -race -cover ./...
gofmt -l .            # must print nothing
golangci-lint run
```

All of these must pass before you say a task is done. Do not report success on
code you have not compiled.

## Non-negotiable rules

**Credentials never leave the process.** Not in logs, not in errors, not in the
inventory, not in exported reports, not in test fixtures — not even partially
masked. `probe.Credentials` implements `String()` and `GoString()` returning a
redacted placeholder; never add a field or a format verb that defeats that.

**No real hostnames.** This repository is public. Every example, fixture and
test uses `example.com` or `example.invalid`. If you see anything that looks
like a real internal hostname, stop and flag it.

**`context.Context` threads through everything that touches the network.**
First parameter, always. Never `time.Sleep` for a timeout, never a package-level
`http.DefaultClient` for a probe.

**Probes do not retry.** Retry lives in `internal/collect`. A probe that sleeps
or loops is a bug.

**The generic probe's vocabulary is frozen.** `json`/`xml`/`header`/`plaintext`/
`regex` plus `cleanRegex`. Do not add conditionals, loops, multi-step requests,
variable capture or templating. Anything needing those needs a Go probe. This
line is the whole defence against becoming a bad interpreter in YAML.

**Facts and judgement stay separate.** `probe.Observation` records what was
seen. Severity is computed later from policy. Never put a verdict in an
Observation.

**Time is a parameter.** Evaluation takes an `asOf`; it does not call
`time.Now()` internally. Tests must be deterministic a year from now.

## Layout

```
cmd/enodia/          CLI entry point
internal/probe/      probe interface, HTTP helper, one file per product
internal/version/    version normalisation and comparison
internal/collect/    concurrent runner, retry policy
internal/inventory/  JSONL read/write
internal/config/     config schema, env interpolation, credential store
internal/resolver/   lifecycle data sources (endoflife.date, GitHub releases)
internal/evaluate/   patch/cycle/major axes, policy, severity
internal/render/     table, JSON, HTML, Prometheus
```

Layers depend downward only. `internal/probe` must not import `internal/config`
or `internal/resolver`.

## Adding a probe

One product, one file, `internal/probe/<product>.go`. Register it explicitly in
`registry.go` — there is no `init()` self-registration, because that file is
meant to read as a table of contents.

Every probe needs a recorded vendor response in `internal/probe/testdata/`
named `<product>_<version>.<ext>`, and a test that parses it. A probe without
testdata does not get merged. Scrub the fixture before committing.

Wrap every returned error with a sentinel from `errors.go` — `ErrUnreachable`,
`ErrAuth`, `ErrNotSupported`, `ErrUnparseable`. The distinction decides whether
the runner retries and whether the user or the project is at fault.

## Style

Ordinary, boring Go. Explicit over clever. This tool holds production
credentials to other people's infrastructure; readability is a security
property, not an aesthetic one.

Comments explain *why*, never *what*. If a line needs a comment to say what it
does, rewrite the line.

Errors are wrapped with `%w` and enough context to locate the failure without a
debugger. No bare `return err` at a layer boundary.

SPDX header on every `.go` file:

```go
// SPDX-License-Identifier: AGPL-3.0-or-later
```

Commits follow Conventional Commits: `feat(probe): add Nextcloud support`.

## Working style

Say when you are unsure rather than producing confident-looking guesses,
especially about vendor API shapes — those are exactly where a plausible
invention costs hours.

Do not add dependencies without asking. The current tree is stdlib-only apart
from cobra and a YAML parser; every addition widens the supply-chain surface of
a tool that holds admin tokens.

Prefer finishing one vertical slice over scaffolding many empty packages.
