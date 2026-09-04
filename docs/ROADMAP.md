# Roadmap

Not dates. Order of work, and what each step unblocks.

## Done

- `internal/probe` — interface, HTTP helper, TLS settings, typed errors
- `internal/probe` — 29 products: the atlassian family (jira/confluence/
  bitbucket/bamboo), artifactory, bitwarden/vaultwarden, elasticsearch,
  generic, gitlab, grafana, jellyfin, jenkins, keycloak, mattermost, mysql,
  nextcloud, owncast, perforce-swarm, portainer, postgresql, redis,
  sonarqube, ssh, teamcity, testrail, vault, vcenter, zou (kitsu alias)
- `internal/version` — normalisation, comparison, cycle matching
- `internal/collect` — concurrent runner, retry policy, warnings
- `internal/inventory` — JSONL writer/reader, schema versioning
- `internal/config` — schema, `${VAR}`/`${VAR:-default}` interpolation,
  named credentials + `credentials_file`, path resolution order
- `internal/resolver` — endoflife.date with on-disk cache, GitHub Releases
  fallback
- `internal/evaluate` — three axes per D6, policy, reason/severity split
- `internal/history` — dated inventory tracking
- `internal/serve` — snapshot-only HTTP, ticker-collects/handler-reads per D14
- `cmd/enodia` — collect, check, export, config, products, version,
  completion, history, serve, about
- `internal/render` — compact/lifecycle/drift/fleet views; table, JSON,
  Prometheus textfile, single-file HTML
- Packaging — `.goreleaser.yaml`, `make enodia` with version/commit/date
  baked in via `-ldflags`
- Windows resource embedding — `build/windows/` (icon, version-info `.rc`
  template, manifest) compiled by `make windows-resources`/`windows-exe`
  into `cmd/enodia/resource_windows_amd64.syso` via mingw-w64's windres;
  wired into `.goreleaser.yaml`'s `before.hooks` and the release workflow
  (mingw-w64 installed there with `continue-on-error`, so its absence
  degrades only that one artifact). Verified end-to-end: real multi-size
  icon and version block land in a real cross-compiled `.exe`, console
  subsystem kept intact (no `-H=windowsgui` — that's for GUI apps, and
  would hide this CLI's own stdout/stderr). windows/arm64 has no
  equivalent yet — Debian's mingw-w64 ships no aarch64-w64-mingw32-windres
- CVE correlation via OSV.dev — investigated twice, deferred both times;
  see DECISIONS.md D18
- Tests on recorded fixtures, offline, `-race` clean; every new probe
  live-verified against a real instance (Docker or the user's own
  production) before being written, not just against hand-built fixtures

## Next — settings.yaml

`internal/settings`. Personal display defaults, separate from `enodia.yaml`
(see DECISIONS.md D19 for why: targets/credentials are shared prod data,
display prefs are per-operator).

- Same resolution pattern as config (`internal/config/paths.go`):
  `--settings`, `$ENODIA_SETTINGS`, `./enodia.settings.yaml`,
  `./.enodia.settings.yaml`, `$XDG_CONFIG_HOME/enodia/settings.yaml`,
  `/etc/enodia/settings.yaml`. Missing file is not an error — same as no
  config: fall back to built-in defaults.
- `render.default_view` — compact/lifecycle/drift/fleet, used by `check`
  and `export` when `--view` is not passed. Precedence: flag > settings >
  built-in default (`compact`)
- `html.assets`: `inline` (default, today's fully offline single file) or
  `cdn` (Bootstrap + Bootswatch from jsdelivr). Defaulting to `inline`
  preserves the closed-network guarantee; `cdn` is opt-in only, and the
  generated file must carry its own visible warning that it needs internet
  access, not just a note in the CLI output
- `html.view` — reuse the existing `View` type (compact/lifecycle/drift/
  fleet) instead of inventing a second vocabulary; `export --format html`
  gains a `--view` flag exactly like the table renderer already has,
  defaulting to all four stacked sections (today's behaviour) when unset
- `fleet` view gains a reachability/health column (built from Observation
  errors, not Assessments — D7) so "table of versions + which are up" is a
  single view, not a new one
- `html.theme` — a Bootswatch theme name, meaningful only when
  `html.assets: cdn`. This is the default baked into every page generated
  with that settings.yaml (so an operator sets it once for themselves in
  settings.yaml, defaulting to Bootswatch's own "Default" theme when
  unset), rendered as the page's initial stylesheet. A `<select>` in the
  page then lets a given *viewer* override it for themselves, writing the
  choice to that browser's `localStorage` — read back and applied on
  every later load. If the stored value is missing, corrupted, or no
  longer names a real Bootswatch theme, it resets to "Default" (never the
  settings-baked value, and never an error) exactly as asked

## Then — packaging: multiplatform builds

- `make dist`: cross-compile `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
  `windows/{amd64,arm64}` with the same `-ldflags` as `make enodia`. No
  CGO anywhere in the tree, so this is a plain `GOOS`/`GOARCH` matrix loop
- Treat this as the pre-goreleaser stopgap, not a permanent parallel path —
  `.goreleaser.yaml` already owns cross-platform release artifacts plus
  checksums/signing (D17); `make dist` should stay a thin dev convenience
  that goreleaser's config can absorb later rather than diverge from

## Later

- windows/arm64 resource embedding — needs llvm-mingw (or another
  aarch64-capable resource compiler) in place of mingw-w64; not evaluated
- Revisit CVE correlation via OSV.dev if a workable data source appears —
  see DECISIONS.md D18 for exactly what was tried and why it's closed, not
  just deferred

## Deliberately not planned

- Hosted SaaS
- A refresh button that triggers collection
- Any growth of the generic probe's vocabulary
- Built-in authentication for `serve`
