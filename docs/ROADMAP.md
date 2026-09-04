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
  into `cmd/enodia/resource_windows_{amd64,386}.syso` via mingw-w64's
  windres (x86_64 and i686 flavors, checked independently — one missing
  doesn't block the other); wired into `.goreleaser.yaml`'s `before.hooks`
  and the release workflow
  (mingw-w64 installed there with `continue-on-error`, so its absence
  degrades only that one artifact). Verified end-to-end: real multi-size
  icon and version block land in a real cross-compiled `.exe`, console
  subsystem kept intact (no `-H=windowsgui` — that's for GUI apps, and
  would hide this CLI's own stdout/stderr). windows/arm64 has no
  equivalent yet — Debian's mingw-w64 ships no aarch64-w64-mingw32-windres
- `make dist` — `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
  `windows/{amd64,arm64,386}`, same `-ldflags` as `make enodia`,
  windows/amd64 and windows/386 picking up the icon/version resource via
  `windows-resources` (both mingw-w64 windres flavors are just an
  `apt install mingw-w64` away, unlike arm64's). `.goreleaser.yaml` gained
  a second build (`enodia-windows-386`, since Go never supported
  darwin/386 — it can't share enodia's goarch list) folded into the same
  archives. Verified with a real `goreleaser check` and a
  `--snapshot --clean --skip=docker,sign,publish` run, not just `make
  dist`: all seven binaries have the right file type (ELF/Mach-O/
  PE32/PE32+), the resource lands correctly in windows/amd64 and
  windows/386 and is correctly absent from windows/arm64. macOS ships
  unsigned — no Apple Developer Program membership needed for this; the
  project's existing cosign signature over `checksums.txt` (D17) already
  gives independent supply-chain verification for every platform,
  Apple-signed or not. A first Gatekeeper launch will still warn
  "unidentified developer" (routine for curl/browser-downloaded CLI tools,
  cleared via `xattr -d com.apple.quarantine` or right-click → Open) — not
  something to design around
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

## Later

- CI: build inside the user's own `epicmorg/debian:trixie-develop` image
  (already carries Go + mingw-w64) instead of `apt-get install mingw-w64`
  in release.yml. Scope still open — pending decision is whether this
  replaces only the windows-resources step (a plain `docker run` before
  `goreleaser-action`, no risk to the existing native `go build`/docker
  buildx/cosign steps) or the whole release job runs inside the image
  (needs docker-in-docker for buildx/push and confirmation cosign's OIDC
  flow still works from inside a container) — explicitly deferred, not
  decided
- windows/arm64 resource embedding — blocked on the same image gaining
  llvm-mingw (aarch64-capable; Debian's mingw-w64 package isn't), which
  the user plans to add to `epicmorg/debian:trixie-develop` later
- Revisit CVE correlation via OSV.dev if a workable data source appears —
  see DECISIONS.md D18 for exactly what was tried and why it's closed, not
  just deferred

## Deliberately not planned

- Hosted SaaS
- A refresh button that triggers collection
- Any growth of the generic probe's vocabulary
- Built-in authentication for `serve`
