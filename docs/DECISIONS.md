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
`json` / `xml` / `header` / `plaintext` / `regex`, plus `clean_regex`.

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
There is no `--as-of` CLI flag today — `asOf` is always sourced internally,
never typed by a user — but taking it as a plain parameter here means adding
one later (e.g. "what dies before next budget year") would just be plumbing
a value through, not restructuring how time enters the evaluation path.

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

**Revisited:** `release.yml`'s job now runs inside the user's own
`ghcr.io/epicmorg/debian:trixie-develop` image via `jobs.<id>.container:`, not bare
`ubuntu-latest` with `apt-get install mingw-w64`. That image already
carries Go, mingw-w64 (windows/amd64 and windows/386's resource icons —
see ROADMAP.md's Windows resource embedding entry), and llvm-mingw
(windows/arm64's, which Debian's own mingw-w64 package cannot produce at
all), so this is what actually gets real tagged releases the arm64 icon,
not just local/manual runs. It is a sibling-container setup, not
docker-in-docker: the job's container bind-mounts the runner's existing
`/var/run/docker.sock` and talks to it directly, the same daemon the
runner itself would have used — confirmed live, no `--privileged` needed,
because the image already runs as root by default. The image ships no
`docker` CLI or buildx plugin at all, so those get `apt-get install`ed as
an explicit step; everything else (`docker/setup-qemu-action`,
`setup-buildx-action`, `sigstore/cosign-installer`, `docker/login-action`,
`goreleaser-action`) is unchanged, since JS actions running inside a
`container:` job is itself a well-supported, ordinary GitHub Actions
feature, not something specific to this setup.

Release now fires only for a tag actually reachable from `origin/master`
(`git merge-base --is-ancestor`), not merely one shaped like a release tag
pushed from anywhere — the `on.push.tags` glob alone can express the
tag's shape but not where it came from.

Tags became `MAJOR.MINOR.PATCH+BUILD` with no `v` prefix (e.g. `1.2.3+4`),
not the originally-requested `MAJOR.MINOR.PATCH.BUILD`: confirmed live
that goreleaser hard-fails release ("invalid semantic version") on a
literal four-dot tag unless `--skip=validate` is passed — and that flag
also disables goreleaser's dirty-worktree check, which is not something to
run permanently in a release pipeline just to tolerate one tag's shape.
`+BUILD` is valid semver build metadata and parses cleanly with no skip
flags at all; `.Version` renders as the full `1.2.3+4` string, which
Makefile's `VERSION_CSV` now parses into all four FILEVERSION components
(a three-part tag, or none at all, still falls back the way it always
did). The one place this "+" needed handling rather than just working: an
OCI/Docker tag reference flatly disallows the character (confirmed:
`docker tag foo:1.2.3+4` — "invalid reference format"), so
`dockers_v2.tags` renders it through goreleaser's `replace` template
function first; the `org.opencontainers.image.version` annotation keeps
the raw `+4` since annotations carry no such restriction and losing it
there would be a pointless loss of information.

**Verified, and what wasn't:** the docker-socket mount, installing
`docker.io`/`docker-buildx` inside the image, goreleaser accepting
`1.2.3+4` tags (both with and without a `v` prefix) with no skip flags,
`VERSION_CSV`'s four-part extraction, and the `replace` template function
itself (via a real local archive-name build) were all exercised directly.
An actual push to `ghcr.io/epicmorg/enodia` or a real GitHub Release
creation were not — reproducing those locally needs real credentials
against the project's live infrastructure, which is not something to fake
one's way into just to finish testing a workflow file.

**Revisited: the same image also pushes to Docker Hub and Quay,** not
GHCR alone. Unlike GHCR, neither piggybacks on `GITHUB_TOKEN` — both need
real, separately-minted credentials, which live as org-level (not
repo-level) GitHub secrets (`DOCKER_SERVER_LOGIN`/`DOCKER_SERVER_KEY`,
`QUAY_SERVER_LOGIN`/`QUAY_SERVER_KEY`/`QUAY_SERVER_URL`) this repo
consumes but doesn't mint or rotate. `QUAY_SERVER_URL` is templated into
`dockers_v2.images` via `{{ .Env.QUAY_SERVER_URL }}` (passed through from
the secret in `release.yml`'s `goreleaser-action` step) rather than a
literal `quay.io`, since that org-level value, not this repo, is the
source of truth for which Quay host is actually in use. Verified live
(without pushing): a real local multi-arch `docker buildx` build via
`goreleaser release --snapshot --skip=sign` (snapshot mode already implies
`--skip=publish`) produced correctly tagged `amd64`/`arm64` manifests for
all three registries, confirming the template resolves before ever
touching real registry credentials.

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

**Also considered and closed: GitHub Security Advisories (GHSA).** Checked
live against the real API, not assumed. `GET /advisories?ecosystem=`
accepts exactly: `rubygems, npm, pip, maven, nuget, composer, go, rust,
erlang, actions, pub, other, swift` — language package-manager ecosystems
only, the same category OSV already covers and that was never enodia's
gap (enodia probes standalone server software, not libraries). There is
no distro or generic-product ecosystem at all, not even one with OSV's
epoch problem. Atlassian's CVE-2023-22515 (the same Confluence RCE used
above) does exist in GHSA's index, but as `"type": "unreviewed"` with
`"vulnerabilities": []` — an empty array, no structured affected-version
range whatsoever, just the CVE text and a link to NVD. That is strictly
less useful than OSV's own zero-results for Atlassian: it can confirm a
CVE ID exists but can never answer "is this specific version affected,"
which is the only question worth asking (D7: a fact enodia could act on,
not a maybe). And on the open-source side it is worse, not equal: the
exact Redis CVE (CVE-2024-31449) used above to demonstrate OSV's epoch
bug is entirely absent from GHSA's index — zero results, not merely
unmatchable. GHSA solves neither of D18's two original problems and adds
no new capability enodia doesn't already get from OSV; there is no
version of this worth revisiting without a genuinely different data
source, per the "Cost accepted" paragraph above.

---

## D19 — Display settings are a separate file; HTML export stays offline by default

**Decided.** A new `settings.yaml` (own resolution order mirroring
`internal/config/paths.go`: `--settings`, `$ENODIA_SETTINGS`,
`./enodia.settings.yaml`, `./.enodia.settings.yaml`,
`$XDG_CONFIG_HOME/enodia/settings.yaml`, `/etc/enodia/settings.yaml`),
not a new section in `enodia.yaml`.

`enodia.yaml` is shared, often version-controlled, prod-facing data:
targets and the credentials to reach them. Display preferences — default
`--view`, whether HTML export pulls Bootstrap from a CDN, which Bootswatch
theme — are per-operator, per-workstation choices with no bearing on what
gets probed. Folding them into one file means either document changes
every time someone changes their preferred table view, or an operator's
personal taste leaks into a file other people read to find out what
infrastructure is being monitored. A missing `settings.yaml` is not an
error, exactly like a missing `enodia.yaml` config section falls back to
built-in defaults — this file is entirely optional.

The single-file HTML export (`internal/render/html.go`) is currently
inline-CSS-only with zero external resources, so it renders identically
inside a closed network with no path to any CDN. Adding Bootstrap +
Bootswatch theming is worth doing, but only as an explicit opt-in
(`html.assets: cdn` in settings, default stays `inline`) — flipping the
default would silently break every existing closed-network deployment the
first time someone regenerates a report. When `cdn` is chosen, the
generated HTML file itself must carry a visible warning that it needs
internet access, not just a note printed to the CLI at export time, since
the file gets copied and opened somewhere else entirely.

HTML view selection reuses the existing `render.View` type
(compact/lifecycle/drift/fleet) rather than inventing a parallel
"HTML views" vocabulary — `export --format html` gains a `--view` flag the
same shape as the table renderer's, so "just the fleet table" is the
existing fleet view, not a new concept. The fleet view needs a
reachability/health column added (from `Observation` errors, per D7 —
facts, not judgement) to fully cover "table of versions + which are up",
since that case was the original motivation for touching HTML rendering
at all.

**Rules out:** a `settings:` block inside `enodia.yaml`. A refresh/live
theme-fetch mechanism — Bootswatch CSS is fetched by the browser viewing
the exported file, same as any other CDN asset in `cdn` mode; enodia never
fetches it itself (D14 still holds: no network calls outside collection).

**Cost accepted:** two optional config files to resolve and document
instead of one. `html.theme` is meaningless dead configuration whenever
`html.assets: inline` (the default), which is an acceptable amount of
"the setting only matters if you opted into the other setting" — the
alternative (nesting theme under assets in the schema) was judged not
worth the added schema depth for a single dependent field.

**Implemented** as `internal/settings` + `internal/render`'s `HTMLOptions`.
One detail worth being explicit about, since an earlier draft of this
decision got it backwards: the theme-picker script's fallback target for a
missing/unrecognised `localStorage` value is the *resolved* theme this
exact page was generated with (`settings.EffectiveTheme()` — the
operator's own `html.theme`, or Bootswatch's "default" only when they
never set one) — never a hardcoded theme independent of what the operator
configured. An operator who sets `html.theme: lumen` gets reports that
always settle back on lumen; the "default" fallback only ever shows up for
an operator who genuinely never configured a theme at all. The same
resolved value is both the page's initial `<link>` href and the script's
`BAKED` constant, so there is exactly one source of truth for it, not
two that could drift apart.

**Also implemented:** row highlighting in CDN mode, by request once the
theme picker existed — a row's `RowTone` (`ToneGood`/`ToneInfo`/`ToneWarn`/
`ToneBad`) maps to Bootstrap's own `table-success`/`-info`/`-warning`/
`-danger` classes, which every Bootswatch theme redefines consistently, so
the exact same class name reads as that theme's own red/yellow/green
instead of a color enodia would have to hardcode and re-tune per theme.
`RowTone` is deliberately its own type, not a reuse of `evaluate.Severity`:
the fleet view's tone comes from `Observation.OK()`, a fact per D7, and
giving a fact a type named "Severity" would blur exactly the line D7
exists to keep, even though both end up picking the same visual class.
`lifecycle` and `drift` tone by their own axis's severity rather than
`OverallSeverity()`, for the same reason those views show their own axis's
data rather than everything at once: a row there is red because that row's
own focus is critical, not because some other, unrelated axis was worse.

**Bug found and fixed:** the initially-pinned `bootswatchVersion` (5.3.3)
was already stale by the time this shipped — Bootswatch's "brite" theme
didn't exist in that release yet, so choosing it 404'd. Worse, `"default"`
404'd at *every* version tried, including the current one: there is no
`default` folder in bootswatch's own npm/CDN package at all (confirmed
live via jsdelivr's package file listing) — bootswatch.com's own site
lists "Default" as if it were a theme, but it's actually just a link
straight to plain Bootstrap. `ThemeDefault` now reproduces that correctly,
loading the `bootstrap` package directly instead of guessing a bootswatch
path that never existed. Both `bootswatchVersion` and the new
`bootstrapVersion` are bumped to 5.3.8 and kept as one Go constant equal to
the other, since Bootswatch tags a release for every Bootstrap release it
tracks — there is no scenario where they should legitimately diverge.

**Also added:** `ThemeNone` (no stylesheet at all — the internet-access
warning is skipped too, since it would be false) for embedding the report
into a page that already loads its own Bootstrap; and CDN racing —
`html.cdn: auto` (the default) fires a `HEAD` request at both jsdelivr and
cdnjs (identical mirrors of the same files) and upgrades to whichever
answers first via `Promise.any`, so one CDN being blocked or slow on a
given network doesn't take the report's styling down with it.
`html.cdn: jsdelivr`/`cdnjs` opts out of racing entirely, back to a plain
synchronous `<link>`. The very first paint, and any viewer with JavaScript
disabled, always gets jsdelivr's URL — racing only ever upgrades the
stylesheet after that initial render, it never blocks or changes it. This
is a `settings.yaml`-only knob, same as assets/theme: a once-per-operator
default, not a per-export flag.

**Also added:** every report (inline and CDN alike) now ends with a
`<footer>` crediting the project and linking back to
`github.com/EpicMorg/enodia`; CDN-mode reports add a second line crediting
Bootstrap and Bootswatch by name with a link to each and a note that both
are MIT licensed — this repository never bundles their code (it is only
ever loaded from a CDN, at view time, by whoever opens the report), so this
footer line is the actual point of compliance/courtesy, not the license
files of a dependency that isn't vendored. `ThemeNone` skips this credit
line too, matching the internet-access warning it already skips: neither
Bootstrap nor Bootswatch is loaded in that mode, so crediting them would be
false. See README.md's "Third-party assets" for the same reasoning aimed
at a human reader rather than at this file's usual future-maintainer
audience.

The CDN warning alert also became `alert-dismissible` with a working close
button, deliberately without pulling in `bootstrap.bundle.min.js`:
Bootstrap's own Alert component needs that whole JS bundle to dismiss
itself, and the four-line vanilla-JS click handler already living in this
report's one `<script>` tag (see `cdnModeScript`) does the same thing
without adding a second CDN fetch just for one button.

---

## D20 — Termux/Android gets its own `android_arm64` build, not a PIE hack on `linux_arm64`

**Decided.** A separate goreleaser build (`GOOS: android`, `GOARCH: arm64`
only) and archive (`enodia_android_arm64.tar.gz`), and `install.sh` picks
it over the plain `linux_arm64` one whenever `$TERMUX_VERSION` is set.

Found live, via `get.enodia.sh/unix` on a real Termux device: the
`linux_arm64` binary failed to exec at all, Bionic's dynamic linker
rejecting it with `"... has unexpected e_type: 2"`. `e_type: 2` is
`ET_EXEC` — Android has refused to exec anything but a PIE (`ET_DYN`)
binary since Lollipop, a kernel/linker-level policy, not a libc quirk.
`uname -s` still reports `Linux` on Termux (same kernel), so `install.sh`'s
existing OS detection alone can't tell a real Linux userspace apart from
an Android one.

**Why not just add `-buildmode=pie` to the existing `linux` build?**
Verified live (via `qemu-user` inside `debian:trixie`/`alpine:3.20`
containers) that this trades one platform's breakage for another's: Go's
PIE binaries for `linux/arm64` carry a hardcoded `PT_INTERP` of
`/lib/ld-linux-aarch64.so.1` — real glibc systems (Debian) happen to have
that path and load fine, but Alpine (musl, no such path at all) fails with
`No such file or directory` before the binary's own code ever runs, even
though the binary needs no actual shared library (`readelf -d` shows zero
`NEEDED` entries either way — Go's runtime is still fully static, cgo or
not). Alpine is a real shipped target here (the `.apk` package), so this
would fix Termux by breaking a platform already in production.

**The actual fix is `GOOS=android`, a distinct target Go already
supports.** Built and verified live: `CGO_ENABLED=0 GOOS=android
GOARCH=arm64 go build` produces `ET_DYN` with `PT_INTERP` set to
`/system/bin/linker64` — a real path guaranteed to exist on any Android
device (part of the base system image, entirely outside Termux's own
`$PREFIX` sandbox), so it carries none of the musl/glibc path-guessing
problem the PIE hack above has.

**Termux detection uses `$TERMUX_VERSION`, not the `$PREFIX` install.sh
already checks for its directory-writability fallback.** `$PREFIX` is
Termux's own variable too, but it's a generic enough name that other,
unrelated shells/build environments occasionally export it for their own
reasons. That ambiguity is a low-stakes risk for the writability fallback
(worst case: installs into an unexpected-but-harmless directory) but a
high-stakes one here — guessing wrong means downloading a binary this
process's real OS categorically cannot execute at all, no fallback
possible. `$TERMUX_VERSION` is Termux's own unambiguous self-identifying
variable, set in every interactive Termux shell, and not a name plausibly
reused elsewhere.

**Only `arm64`, not `amd64`/`386`/`arm` too.** Verified live: Go's
`android/arm64` is the only android `GOARCH` supporting pure internal
linking (`CGO_ENABLED=0`, no extra toolchain). `android/amd64`,
`android/386`, and `android/arm` all hard-require external (cgo) linking
against an Android NDK cross-compiler — `"requires external (cgo) linking,
but cgo is not enabled"`, not something a build flag works around. Nothing
in this project's build image (`ghcr.io/epicmorg/debian:trixie-develop`)
carries the NDK today, unlike `mingw-w64`/`llvm-mingw` for the Windows
builds. `arm64` alone covers essentially every real Android device in use
today (32-bit Android and x86 Android are both long past relevance), so
this is deferred rather than blocking — see ROADMAP.md's "Later".

**Rules out:** `-buildmode=pie` on the existing `linux` build (breaks
Alpine, see above). Detecting Termux via `$PREFIX` alone for the OS/archive
decision (too easily a false positive elsewhere, and the failure mode of a
false positive here is total, not recoverable). Building all four android
`GOARCH`es now (needs an NDK this project doesn't have access to add to
the shared build image without the user's own separate work there).

**Cost accepted:** a fifth goreleaser build id and a third archive OS to
keep straight. `install.sh` gained one more branch. android/{amd64,386,arm}
stay unsupported until the build image gains an NDK.

**Revisited: rooted devices (Magisk/KernelSU) can still fail to exec the
binary as a normal user, even though it's the right archive.** Live
report: worked fine after `su` + a full path, failed as the ordinary
Termux user with the binary's own path showing up where an argument
should be (cobra: `unknown command "<path-to-enodia>" for "enodia"`) —
confirmed this reproduces on a plain `enodia version`, not just from
inside `install.sh`, so it's not this project's shell script. Matches a
known, open, already-being-fixed upstream bug:
[termux-exec#40](https://github.com/termux/termux-exec/issues/40) —
`termux-exec`'s own C code fails to recognize "alternative entrypoint"
process contexts (Magisk, KernelSU, `run-as`, ADB) when exempting
`/system/bin/linker64` from Android's execution restrictions, and a
rooted device commonly puts even an ordinary Termux session into exactly
that kind of context. The documented upstream workaround is the same
`su`-based one that resolved it here; two PRs fixing the context
detection are open upstream but not yet merged. Nothing to change on
this side — this is `termux-exec`'s own linker-exemption logic
misidentifying the process context it's running in, not something a
downstream binary's build or `install.sh` can route around. Expected to
not reproduce at all on a non-rooted device, which never enters one of
these alternate contexts in the first place.

---

## D21 — No Kafka probe: the wire protocol has no anonymous version field at all

**Decided (for now).** Not implemented. `kafka` stays off the roadmap's
"Next" list, blocked pending a workable data source — the same shape of
decision as D18, not a "get to it eventually."

Confirmed live against a real `apache/kafka:latest` broker (logged version
4.3.1): `ApiVersionsRequest` (API key 18, the one pre-authentication
request every Kafka client sends as part of connecting) replies with
nothing but `error_code` plus an array of `(api_key, min_version,
max_version)` triples — 91 entries on this broker, none of them a software
version string. This is the wire protocol's *entire* anonymous surface;
there is no `hello`/`buildInfo`-equivalent command (contrast D10's mongodb
probe, which has exactly that). Raw hex of the reply confirmed no ASCII
version string is hiding anywhere in it either.

**Rules out:** a MongoDB/Zabbix-style "run one command, read one field"
probe — that field does not exist on the wire at all, so there is nothing
to hand-decode.

**Also rules out (for now):** inferring the release from the
`ApiVersionsResponse`'s per-API max-version numbers. Real tools do this,
but only as a best-effort range ("2.8-3.2ish"), not an exact version: a
lookup table mapping every combination of max-versions to a specific Kafka
release would need updating on every Kafka release just to keep working,
cannot distinguish patch releases at all (a bugfix release typically bumps
no API's max version), and is exactly the kind of confident-looking,
silently-stale guess docs/CLAUDE.md's "Working style" section asks not to
ship. `internal/evaluate`'s patch axis (D6) would have nothing trustworthy
to compare against.

**What would unblock this:** JMX (`kafka.server:type=app-info` exposes the
real version string as an MBean attribute) is the standard way tools like
Kafka Exporter get this — but it is a materially different protocol (RMI,
not a raw request/reply over the broker's own port), off by default, and
its own port/auth model. That is a new kind of probe transport, not a
one-file addition alongside mysql.go/redis.go/mongodb.go — deferred rather
than folded in as a variant of this decision.

---

## D22 — No Redmine probe: version needs a session-cookie login, not just credentials

**Decided (for now).** Not implemented. `redmine` stays off the roadmap's
"Next" list, blocked pending a workable auth path — same shape of decision
as D18 and D21.

Confirmed live against a real `redmine:latest` instance (actual version
7.0.1, read from `lib/redmine/version.rb`): nowhere anonymous discloses
it.

- The homepage, `/login`, and every static asset checked carry no version
  anywhere — no meta tag, no HTTP header, no footer text beyond "Powered
  by Redmine © `<year>` Jean-Philippe Lang".
- Redmine's own Atom feeds (`/issues.atom`, `/news.atom`, ...) do emit a
  `<generator uri="https://www.redmine.org/">Redmine</generator>` tag —
  contrast the `wordpress` probe's feed generator, which is exactly this
  shape but with a `version` attribute Redmine's simply doesn't carry.
- The one page that does show it, `/admin/info`, requires an
  authenticated session and redirects an anonymous request straight to
  `/login` — confirmed this happens even with a correct `Authorization:
  Basic` header (`admin`/`admin`, Redmine's own well-known default): HTTP
  Basic is not accepted on this controller action at all, only a session
  cookie obtained by actually submitting the login form.
- REST API JSON endpoints (`/issues.json`, checked anonymously) carry no
  application-version field either — this isn't only a web-UI limitation.

**Rules out:** every existing `AuthKind` (`bearer`, `token-header`,
`basic`, `password`). None of them represent "POST a login form carrying
a CSRF token read off a prior GET, then keep the session cookie for a
second request" — a fundamentally heavier flow than any probe in this
tree performs today, closer to browser automation than to
`Authorization: <scheme> <value>`. Building it as a Redmine-specific
one-off would also mean Target growing a cookie jar for exactly one
probe, which no other probe needs.

**What would unblock this:** either Redmine adding version disclosure
somewhere genuinely anonymous (unlikely — this reads as a deliberate
choice, not an oversight, the same direction WordPress's ecosystem has
been pushed by hardening guides), or a real, generalizable case for
form-login-with-CSRF support landing in this tree for its own reasons
first — not one added solely to unblock this single product.

**Revisited, and this rule held:** `synology-dsm` (`internal/probe/
synologydsm.go`) needed a login step too — `SYNO.API.Auth`'s `login`
method, session id, and (with CSRF protection on) a `SynoToken` — but it
was accepted rather than deferred like Redmine, because it turned out to
be a materially lighter case, not an exception to this rule: a plain
JSON API taking `account`/`passwd` as ordinary query parameters and
handing back the session id as an ordinary JSON field, confirmed live.
No HTML page to scrape a CSRF token out of, no cookie jar — `_sid`
travels as a query parameter on the next call. Redmine's blocker is
specifically the HTML-form-plus-cookie shape, which this still doesn't
provide a generalizable answer for; Redmine stays deferred.

---

## D23 — SSH/OS-identification probes: twenty-five made it in, three did not, for concrete reasons

**Decided.** `internal/probe/osrelease.go`'s family probe (D9: checks an
identity field, here `/etc/os-release`'s `ID`) covers debian, ubuntu,
fedora, rhel, rocky-linux, almalinux, oracle-linux, amazon-linux,
opensuse, alpine-linux, centos-stream, slackware, and freebsd (at
`/var/run/os-release` — see osrelease.go's doc comment). `macosProbe`
(`internal/probe/macos.go`, `sw_vers` instead of an os-release file) is
its own file, not part of that family, since sw_vers's output shape is
different. Every one of these was checked against a real, live system,
not assumed from documentation. This entry records exactly why the other
eleven names on the original request list are not implemented — each for
a different, confirmed-live reason, not a blanket "too hard":

- **`fortios`, `cisco-ios-xe`** — both are licensed commercial network
  appliances with no freely obtainable test image (Fortinet's FortiGate
  VM and Cisco's CSR1000v/Catalyst 8000v both require a vendor account,
  an accepted EULA, and in Cisco's case a CML/VIRL entitlement — none
  obtainable anonymously here). Both also raise a real design question
  this project has not needed to answer yet: FortiGate has a documented
  REST API (`/api/v2/monitor/system/status`) and IOS-XE has
  RESTCONF/NETCONF, either of which fits this project's existing
  HTTP-probe shape far better than screen-scraping an interactive CLI
  session over SSH (the RouterOS probe already made exactly this call —
  HTTP REST over SSH CLI — for the same reason). Shipping either without
  a real device to confirm the actual response shape would be precisely
  the "confident-looking guess about vendor API shapes" docs/CLAUDE.md's
  "Working style" section warns against, so both stay unimplemented
  rather than written blind.
- **`tails`** — a live, amnesic, privacy-focused OS that boots fresh from
  read-only media on every start and is deliberately designed to discard
  state and resist exactly the kind of unattended, persistent,
  credentialed remote access this probe family requires. Implementing
  this would work against what the product is for, not merely be hard to
  test. Not pursued, on principle rather than a tooling gap — the user
  confirmed this stays crossed off entirely, not merely deferred.

**Rules out:** shipping `fortios` or `cisco-ios-xe` today (a licensing/
tooling gap, still open) and `tails` at all (a principled exclusion, not
open). **Does not rule out** revisiting `fortios`/`cisco-ios-xe` once a
real device is available — that's still just "closed, pending one
concrete thing," the same shape D18/D21/D22 draw, not a permanent no the
way `tails` is.

**Revisited: `openbsd`, `netbsd`, `oracle-solaris`, and (a new request)
`opnsense` unblocked via vmactions** — this entry originally listed the
first three as blocked on the same thing, no obtainable pre-installed
image, and a fourth option turned up: [vmactions](https://vmactions.org)
publishes GitHub Actions (`openbsd-vm`, `netbsd-vm`, `solaris-vm`,
`opnsense-vm`) that boot real, pre-built QEMU VM images specifically for
CI use — a fork of `vmactions/shell-openbsd` with a small custom
`workflow_dispatch` job per OS (just `run: uname -sr` or similar) got
each identity string back in the job's own log in 1-2 minutes, no
interactive session or manual QEMU/autoinstall work needed.
`unameFamilyProbe` (`internal/probe/uname.go`) now covers `openbsd`
(`uname -sr` → "OpenBSD 7.9") and `netbsd` ("NetBSD 11.0") — neither
ships an os-release-equivalent file, so `uname -sr`'s
"\<name\> \<release\>" is the identity source instead of D9's usual
identity-field check. `oracle-solaris` (`internal/probe/solaris.go`)
reads `/etc/release` instead: `uname -sr` on Solaris only ever reports
the SunOS kernel version ("SunOS 5.11" for every Solaris 11.x release,
decoupled from the product version), while `/etc/release`'s own
"Oracle Solaris 11.4 X86" line carries the real one. vmactions'
`solaris-vm` builds and republishes Oracle's own free-to-redistribute
Solaris 11.4 CBE (Common Build Environment, meant for exactly this kind
of CI use), not something obtained by working around Oracle's OTN
license. `opnsense` (`internal/probe/opnsense.go`) — a new request,
never in the original blocked list — sits on a FreeBSD base with no
`/etc/os-release` and no single obvious identity file (its version is
split across several files under `/usr/local/opnsense/version/`), so it
runs `opnsense-version` instead, OPNsense's own wrapper that already
picks the right one and prints "OPNsense 26.7 (amd64)" in one command.
`nixos` has no vmactions equivalent (confirmed live: no matching repo in
the `vmactions` GitHub org) — it was unblocked separately, see the
"Revisited: five more products unblocked via real ISO rootfs captures"
note below — so this was a real, if unusually convenient, narrowing of
the blocker for these four products via one mechanism, not a blanket fix
for the whole list. `truenas` was considered at the same time and
initially stayed deferred for the same reasons (no vmactions coverage,
no Docker image running the actual appliance, ISO-only installer) — it
was unblocked separately, later, the same way `proxmox` was: the user
put a real TrueNAS install on a disposable test box and read
`/etc/version` off it directly. See the "Revisited" note further below
for `truenasProbe`'s own detail.

**Revisited: `macos` unblocked immediately** — this entry originally
listed it as blocked on exactly one thing, a real Mac to verify against,
and that arrived within the same day. `macosProbe` is implemented and
confirmed live against a real machine (macOS 15.4, BuildVersion 24E248,
reached over SSH). It deliberately runs `sw_vers`, not `uname -a`: Darwin
folds the machine's own hostname into `uname -a`'s output, which this
probe has no reason to see, let alone store, while `sw_vers`'s three
`ProductName`/`ProductVersion`/`BuildVersion` lines carry none of that.
This is the fastest any item on this list moved from "blocked" to
"shipped" — the blocker really was just "no target," nothing about the
mechanism itself was ever in question.

**Revisited: five more products unblocked via real ISO rootfs
captures, plus legacy CentOS added on request** — `nixos`, `steamos`,
`eurolinux`, `linuxmint`, and `postmarketos` were all listed above as
blocked on "no obtainable image, or no image that correctly reports its
own identity." The user downloaded each product's own official
installer ISO directly, extracted its rootfs/squashfs, and pasted the
real `/etc/os-release` content — a different route than every other
registration in this family (no Docker image, no vmactions, no vendor
cloud image, just the installer medium itself examined offline), but it
produces the same thing D9 needs: a genuine vendor-reported identity
field, not documentation or a guess. All five joined
`osReleaseFamilyProbe` directly:

- `nixos`: `ID=nixos`, `VERSION_ID="26.05"` — confirms the file exists
  and is well-formed; the earlier blocker (`nixos/nix` on Docker Hub
  being the wrong thing entirely) is now moot.
- `steamos`: captured from SteamOS 2 (Debian-based, codename
  "brewmaster") — `ID=steamos`, `VERSION_ID="2"`. The "wrong use case"
  reasoning this entry originally gave for SteamOS was corrected by the
  user: real, legitimate SteamOS build/test machines exist (the same
  shape of "legitimate infrastructure, not a home console" the `macos`
  target already was), so that reasoning no longer applies once such a
  target exists. SteamOS 3.x (Arch-based, the current Steam Deck OS,
  codename "holo") is expected to share the same `ID=steamos` field —
  Valve's own branding is consistent across the rewrite — but this
  hasn't been captured live, only 2.x has; `osReleaseFamilyProbe`'s
  plain `ID=steamos` match covers both without needing to special-case
  either.
- `eurolinux`: `ID="eurolinux"`, `VERSION_ID="8.10"` — the blocker was
  never the identity field, only that no Docker image existed to read it
  from; the ISO always had it.
- `linuxmint`: `ID=linuxmint`, `VERSION_ID="22.3"` — genuinely Mint's own
  identity this time, unlike the Docker Hub image examined earlier
  (`linuxmintd/mint22-amd64`, Mint's own CI build chroot, which reported
  the underlying Ubuntu base instead).
- `postmarketos`: `ID="postmarketos"`, `VERSION_ID="v26.06"` — the
  leading `v` is the vendor's own format, passed through as-is;
  `internal/version.Core` already strips a leading `v`/`V` before
  comparison (the same handling GitHub's `v1.2.3` release tags get), so
  no probe-side trimming was needed.

**Also added on request, not part of the original blocked list:**
`centos` (plain, legacy CentOS Linux — as opposed to `centos-stream`,
its still-current successor). Not part of `osReleaseFamilyProbe`:
confirmed live that CentOS 5 and 6 (`centos:5`, `centos:6` on Docker
Hub) predate the systemd os-release convention entirely — no
`/etc/os-release` at all — while `/etc/redhat-release` has existed
across the whole RHEL family since long before that
(`centosProbe`/`internal/probe/centos.go`, reading `"CentOS release
5.11 (Final)"` / `"CentOS release 6.10 (Final)"` / `"CentOS Linux
release 7.9.2009 (Core)"`). The pattern deliberately requires "CentOS
release" or "CentOS Linux release" immediately after "CentOS ", which a
real CentOS Stream 9's own `/etc/redhat-release`
("CentOS Stream release 9") does not satisfy — confirmed live, so a
Stream instance is never misidentified as legacy `centos` even though
both files exist on both product lines. The point of adding a probe for
an already-dead product: real fleets still run CentOS 5/7 regardless of
upstream's own lifecycle, and that is exactly the situation this
project exists to surface, not paper over by only tracking currently-
supported products.

**`tails` was separately, explicitly ruled out for good** ("cross it
off entirely") rather than revisited — see the "Rules out" note above.

**Revisited: `proxmox` and `truenas` both unblocked the same day,
via real disposable test infrastructure the user provided directly.**
`proxmox` — confirmed live against a real Proxmox VE 9.2.2 host: `GET
/api2/json/version` needs auth (401 without it), and the token shape is
exactly what Proxmox's own docs describe:
`Authorization: PVEAPIToken=user@realm!tokenid=secret`. This needed no
new `AuthKind` — it's a plain `Authorization` header value, and
`AuthTokenHeader` already defaults to that header when none is
specified — so `proxmoxProbe` (`internal/probe/proxmox.go`) is the
first HTTP probe among everything added in this SSH-probe push. The
alternative auth shape, a username/password ticket flow (`POST
/access/ticket` for a session cookie plus a CSRF token), is deliberately
not supported: the same heavier session-login shape D22 already rejected
for Redmine, and Proxmox's own documentation recommends the token for
unattended automation anyway.

`truenas` (`internal/probe/truenas.go`) went through two versions the
same day. First an SSH-based one reading `/etc/version` directly (a
plain `"25.10.7"`, confirmed live, with no os-release involved —
TrueNAS's own `/etc/os-release` reports the Debian 12 base underneath
it, not TrueNAS itself, the same D9 gap `astra-linux`'s messy
`VERSION_ID` had). Then, once the user repurposed the same test box for
a live TrueNAS install with a real API key, `GET /api/v2.0/system/info`
was confirmed live too: 401 without auth, 200 with `Authorization:
Bearer <api-key>` — TrueNAS's API key needs no new `AuthKind` either,
since `AuthBearer` already does exactly that. The HTTP version replaced
the SSH one outright rather than the two coexisting: this project has no
per-product dual-transport fallback mechanism (D2 — one product, one
probe, one file), so once the better-fitting shape was verified there
was no reason to keep maintaining both. Not a redesign forced by new
information, just the natural order two live targets arrived in on the
same day.
