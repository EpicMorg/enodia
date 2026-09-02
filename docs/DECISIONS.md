# Architecture decisions

Settled decisions and the reasoning behind them. Written down so they do not
have to be re-argued, and so that reopening one is a deliberate act rather than
an accident.

Format: what was decided, why, and what it rules out.

---

## D1 — Go, not Python or C#

**Decided.** Go 1.26.

Distribution drives this. The target audience runs infrastructure inside closed
networks: copying one static binary to a jump host is the difference between
"can deploy" and "cannot". A container from `scratch` is ~15 MB against ~150 MB
for a Python image. Cross-compiling for Windows is one environment variable.

A tool carrying admin tokens to Vault and vCenter also benefits from a small
dependency tree.

**Rules out:** dynamic plugin loading, rich reflection-based config binding.
Both were considered and neither is needed — see D2.

**Cost accepted:** slower to write than Python for the author; YAML and JSON
handling is more verbose.

---

## D2 — Probes are compiled-in Go types, not a YAML DSL

**Decided.** One product, one Go file, explicit registration in `registry.go`.

Every vendor API differs. The declarative vocabulary in the original prototype
only looked general because it had been fitted to the fifty services that
happened to be on hand; the first vendor outside that set breaks it.

Encoding vendor knowledge in code means an `if` is just an `if`, readable and
debuggable, instead of a conditional expressed in YAML.

Registration is explicit rather than `init()`-based so `registry.go` reads as a
table of contents and a pull request adding a product shows up in the diff.

**Rules out:** users adding products without a release. Mitigated by D3.

**Cost accepted:** fixing a probe requires a release. Mitigated by a fast
release pipeline and by the generic probe as a stopgap.

---

## D3 — The generic probe exists and is frozen

**Decided.** `product: generic` accepts a parser spec from user config:
`json` / `xml` / `header` / `plaintext` / `regex`, plus `cleanRegex`.

Every organisation has an in-house system that will never get a dedicated
probe. Without an escape hatch those users are blocked on a maintainer.

**The vocabulary does not grow.** No conditionals, no loops, no chained
requests, no variable capture, no templating. A target needing any of those
needs Go code.

This is the boundary that keeps the project from becoming an interpreter
implemented in YAML — the failure mode of Ansible-style tooling, and the reason
the escape hatch is deliberately second-class rather than the main mechanism.

---

## D4 — Collection and evaluation are separate phases

**Decided.** `collect` → `inventory.jsonl` → `evaluate` → assessment → render.

The host that can reach Jira, Vault and vCenter usually has no internet access.
The lifecycle calendars are on the internet. A single-phase design is stuck.

```
enodia collect -c config.yaml -o inventory.jsonl   # inside, no internet
enodia check --from inventory.jsonl                # outside, no access to services
```

`check` without `--from` is just the two phases composed in one process — not a
second code path. Duplicated logic between them means the split is wrong.

**Consequence:** the inventory is a first-class artefact with a schema and a
version, not an in-memory intermediate.

---

## D5 — Inventory format is JSON Lines

**Decided.** One JSON object per line: a header, then observations.

`cat contour-a.jsonl contour-b.jsonl` produces a valid third file. Estates split
across isolated networks need exactly this. Streams without loading everything
into memory; `jq` and `grep` work line-wise.

Extra headers are tolerated on read; the earliest collection time wins, because
a merged inventory is only as fresh as its oldest part.

`schemaVersion` is checked on read. A future version is refused with advice to
upgrade rather than parsed optimistically.

**Cost accepted:** metadata has to live in a header line rather than a wrapping
object. Mildly ugly, worth it.

---

## D6 — Three orthogonal verdict axes, not one status

**Decided.**

| Axis | Values |
|---|---|
| Patch | `current` `behind` `ahead` `unknown` |
| Lifecycle | `active` `security` `eol` `unknown` |
| Newer branch | `latest` `newer` `newer_lts` `unknown` |

The motivating case: Confluence 10 LTS is current within its branch, actively
supported, and a newer major exists. Three independent facts, none derivable
from the others. Collapsing them loses the information the tool exists to
surface.

`ahead` is not exotic — release candidates and calendar lag produce it
routinely.

---

## D7 — Facts and judgement are separate types

**Decided.** `Observation` holds what was seen. `Assessment` holds what we
think about it. Severity is computed by a policy engine over facts.

JSON export therefore emits facts, and a consumer can apply their own policy.
Baking severity into the observation makes that impossible and forces everyone
into post-processing.

---

## D8 — Time is a parameter

**Decided.** Evaluation takes `asOf time.Time`. Nothing in the evaluation path
calls `time.Now()`.

Tests stay deterministic instead of turning red on their own a year from now.
`--as-of 2027-01-01` — "what dies before next budget year" — falls out for
free; retrofitting it later would not.

`check --from` takes `asOf` from the inventory header, so a month-old file is
not silently judged against today.

---

## D9 — Product is declared explicitly, probe verifies

**Decided.** `product: jira` in config selects the probe. The probe checks the
vendor's own identity field and fails with `ErrNotSupported` on mismatch.

Guessing the product from the response was rejected: an explicit config is
reviewable by eye, and pointing a Confluence URL at a Jira entry is a real typo
that should be caught rather than recorded as a wrong fact.

Atlassian products share one manifest endpoint, so one implementation is
registered once per product with a different expected `typeId`. Bitbucket still
reports `stash`.

Probes may fall back to self-identification when `product` is omitted.

---

## D10 — Transport belongs to the probe

**Decided.** `Probe(ctx context.Context, t Target) (Observation, error)`.
`Target` carries a raw address string; each probe parses it.

Redis reports its version through `INFO server`, PostgreSQL through
`SHOW server_version`, MySQL in the handshake packet *before* authentication,
SSH and SMTP in their banners. None of these are HTTP. An interface built
around `*http.Response` would need rewriting on the first one.

A shared `*http.Client` lives on `Target` as a deliberate concession — 90% of
probes are HTTP and connection pooling matters. Non-HTTP probes ignore it.

`context.Context` is mandatory because it is the only mechanism that cancels a
blocked TCP connection.

---

## D11 — Typed errors, retry in the runner

**Decided.** Sentinels: `ErrUnreachable`, `ErrAuth`, `ErrNotSupported`,
`ErrUnparseable`, `ErrSkipped`, `ErrInsecure`. Wrapped with `%w`.

Only `ErrUnreachable` is retried. A rejected token does not improve on the
second attempt, and repeating the request hammers production for nothing.

The distinction also tells the user whose problem it is: `ErrAuth` is their
token, `ErrUnparseable` is our bug — the vendor changed shape and an issue
should be filed.

Retry lives in `internal/collect` so every probe retries identically and no
probe can forget.

---

## D12 — HTTPS first, credentials never on plaintext by default

**Decided.**

Scheme resolution: explicit scheme wins. Absent, try `https` first, fall back to
`http`, warn either way. **Never probe `http` first** — the first request would
carry the credential in the clear, and the later redirect does not un-send it.

An `http://` target with credentials is an error unless
`allow_insecure_transport: true` is set on that service.

Redirects from `https` to `http` are refused: the credential is already on the
request by then.

Scheme discovery is a separate `config resolve` command, not something that runs
every time. It runs without credentials.

---

## D13 — TLS is a structure, not a boolean

**Decided.** Three levels, in descending order of correctness:

1. `ca_file` — a corporate CA bundle. Common and correct; most closed estates
   run their own PKI.
2. `pin_sha256` — pinned leaf fingerprint. Verification without trusting a CA.
3. `insecure: true` — last resort.

`insecure` warns on every run, not only during validation, because it has a
habit of being added "temporarily" and living for years. The flag travels into
the observation, so reports double as a fleet-wide TLS audit.

There is no global `--insecure`. Per service only.

---

## D14 — No built-in web server in the MVP

**Decided.** `export --format html` writes one self-contained file. nginx serves
it; cron or a systemd timer regenerates it.

A refresh button that polls the whole fleet on every click is a self-inflicted
denial of service against your own production. Collection runs on a schedule;
HTTP only ever reads a finished snapshot.

If `serve` is added later, the same rule holds: a ticker goroutine collects, and
handlers read a snapshot pointer. No polling on request, ever.

**Also ruled out:** hosted SaaS. Custody of other organisations' infrastructure
credentials is an unacceptable liability for a one-person project, and the
agent-in-the-network variant is a supply-chain vector any competent security
reviewer would reject.

---

## D15 — Containers run per invocation, not as daemons

**Decided.** `docker run --rm ... check --output /out/index.html`.

`docker exec` into a long-lived container requires a `sleep infinity` process
that does nothing 23 hours a day, and silently stops producing output if the
container dies.

Entry point is the binary, so `docker run` arguments reach the CLI directly.
Runs as a non-root user. Output is written to a temporary file and renamed, so
nginx never serves a half-written page.

---

## D16 — AGPL-3.0-or-later plus a CLA

**Decided.**

AGPL §13 covers the network case, which matters because the tool is intended to
serve HTML over a domain. `-or-later` avoids locking the project into v3
permanently.

The CLA grants the right to relicense under any terms, including proprietary —
without that clause dual licensing is impossible and a commercial licence cannot
be offered. A DCO does not do this.

**This has a deadline.** Once an external contribution is merged without a CLA,
the right is gone and cannot be recovered retroactively.

Known cost: some contributors consider AGPL+CLA asymmetric, and it costs a few
of them. The alternative — pure AGPL, no CLA — permanently forecloses
commercial licensing. There is no third option.

BSL and Elastic License were rejected: not OSI-approved, therefore blocked by
some corporate policies and absent from distribution repositories, which matters
for a tool meant to be installed *inside* corporate networks.
