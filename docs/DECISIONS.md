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

---

## D17 — Cosign keyless signing, dockers_v2, install script on raw GitHub

**Decided.** `.goreleaser.yaml` (v2 schema, verified against
`goreleaser.com/static/schema.json` and goreleaser's own production config
rather than assumed).

**Signing is cosign keyless (Sigstore), not a GPG key.** The CI job's GitHub
OIDC token *is* the signing identity — nothing is generated, stored as a
repository secret, or can leak. Verification is
`cosign verify-blob --certificate-identity-regexp` against the public
transparency log, not a key someone has to fetch and trust first. The
checksums file is signed once rather than every archive individually; the
pushed container is signed the same way, against its digest.

**Container multi-arch build is `dockers_v2`, not `dockers` + `docker_manifests`.**
Upstream marks `dockers_v2`'s name provisional — it becomes plain `dockers`
in goreleaser v3 — but it is the actively maintained path (goreleaser
releases itself with it) and needs one block instead of one per architecture
plus a manifest-merge step. `dockerfile.md`'s own build-context contract
(`$TARGETPLATFORM/<binary>`) is why `Dockerfile` looks the way it does: a
`scratch` image that only copies a CA bundle and the pre-built binary,
never a Go build — goreleaser already cross-compiled every target, and
compiling again in the container would silently make cross-compilation
pointless and slow every release down.

**The GitHub Action wrapper (`action.yml`) is a second, separate Dockerfile**
(`action.Dockerfile`) that *does* build from source and keeps a shell.
`Dockerfile` has neither, on purpose (D15's non-daemon, minimal-surface
container), and `action.yml`'s entrypoint needs `sh -c` to turn its single
`args` string input into argv. Reusing the release image would need a
version-synced `image:` pin updated on every tag; building from source on
each Action run is slower per-invocation but has no moving parts to get out
of sync.

**The install script needs no dedicated host.** `curl -sSL
https://raw.githubusercontent.com/EpicMorg/enodia/master/install.sh | sh`
already satisfies "served from a path, never the site root, never
User-Agent-dependent": raw.githubusercontent.com serves the literal file
identically to every client, with no server-side logic at all. All OS/arch
decisions happen inside the script via `uname`, not on a server.

**Rules out:** GPG-based release signing (a private key to generate, rotate,
and protect becomes part of the project's own attack surface — precisely
what D12/D13's TLS handling and D16's licensing already went out of their
way to avoid taking on elsewhere). A dedicated install domain (one more
thing to register, host, keep TLS current on, and go stale if forgotten).

**Cost accepted:** `dockers_v2` is explicitly provisional upstream and its
name will change; the config will need a rename (not a redesign) when
goreleaser v3 ships. The GitHub Action rebuilds enodia from source on every
invocation rather than reusing a published image.

---

## D18 — CVE correlation via OSV.dev is deferred

**Decided (for now).** Not implemented. The roadmap bullet stays on the
"Later" list, blocked pending a workable data source — reopening this needs
a new source or mapping, not just picking the work back up.

OSV.dev's documented, stable query surface (`POST /v1/query`: package +
ecosystem + version) is built for language package registries (npm, PyPI,
Go, Maven, ...) and Linux distro package managers (Debian, Alpine, ...).
Neither shape fits what enodia's probes report, checked against the live
API rather than assumed:

- Atlassian products (jira/confluence/bitbucket/bamboo) have zero coverage:
  they are not open source, so there is no ecosystem entry point at all.
  Confirmed by looking up a real, well-known CVE directly by ID —
  CVE-2023-22515, the 2023 Confluence broken-access-control RCE — which
  returns 404, not found.
- mysql/postgresql/redis/ssh (openssh) are open source, but the version a
  probe reports is the upstream one (e.g. "7.4.11"), not the
  distro-packaged version OSV's Debian/Alpine ecosystem entries key on
  (e.g. "5:7.0.15-1", carrying an epoch and a packaging revision).
  Comparing one against the other is not merely imprecise: Debian version
  ordering sorts on epoch first, so a bare upstream version (implicit epoch
  0) sorts below any entry with a nonzero epoch regardless of what the
  actual numbers are — every "fixed in this version" range would look
  unfixed. Confirmed concretely: CVE-2024-31449 (a real Redis Lua-sandbox
  RCE) exists in OSV, but its clean range data is keyed by git commit, not
  version; the only version numbers present live in a
  `database_specific.extracted_events` field that is explicitly outside
  OSV's stable schema, CPE-derived, and visibly noisy (an
  `"introduced": "7.4.0-NA"` entry among them).

**Rules out:** wiring `product + probed version` straight into `/v1/query`
as the roadmap bullet originally imagined. For every probe enodia has
today, that would either always return empty (Atlassian) or risk a wrong
verdict (the distro-ecosystem epoch mismatch) — exactly the failure mode
D6/D7 already exist to prevent, applied to a new axis: "has a known CVE" vs
"we know nothing about CVEs for this" must not collapse into each other.

**Revisited and reconfirmed** after being asked to check
`github.com/google/osv-scanner/v2/pkg/osvscanner` and cve.org as possible
ways around this:

- `osvscanner.DoScan`/`DoContainerScan` take lockfile paths, directories or
  a container image — a dependency-manifest scanner, not a
  product-plus-version lookup. The client it uses underneath,
  `osv.dev/bindings/go/osvdev`, is a typed wrapper over the same
  `POST /v1/query` already tested above; it adds no version-matching logic
  of its own, so it inherits the same problem.
- cve.org is the CNA registry a CVE ID's canonical text comes from — it
  carries no machine-checkable affected-version ranges at all. That
  matching layer is exactly what OSV/NVD exist to add on top of it, so it
  does not change the picture either.
- The epoch problem was re-verified live and turned out sharper than
  originally stated: querying OSV's `Debian` ecosystem for `redis` with an
  impossible version (`999.999.999`, chosen to be obviously unaffected by
  anything) still returned 99 findings — every single Debian-ecosystem
  Redis record OSV has. `DEBIAN-CVE-2013-0178` fixed at `2:2.6.0-1`
  illustrates why: Debian orders by epoch first, `999.999.999` carries an
  implicit epoch of 0, and `0 < 2` regardless of what follows — so *any*
  bare upstream version any enodia probe could ever report reads as
  "still affected" by that record. This is not a rare edge case in the
  data; it is how the comparison always behaves once a record's fixed
  version carries a nonzero epoch. Querying with `ecosystem: ""` is worse,
  not better: it returns results (171 of them, for the same impossible
  version) by matching on package name across every ecosystem at once,
  without applying a real version filter at all.

**Cost accepted:** the roadmap bullet stays unimplemented, and the bar to
reopen it is now confirmed higher than "use OSV's official Go client
instead of raw HTTP" — that path is closed, not merely untried. Revisiting
this needs either a per-product mapping from probed version to a queryable
distro/ecosystem identity (fragile, and still leaves Atlassian uncovered),
or a different data source entirely — NVD's CPE-based CVE API 2.0 covers
commercial software like Atlassian's, at the cost of being a second,
differently-shaped external dependency, not evaluated here.
