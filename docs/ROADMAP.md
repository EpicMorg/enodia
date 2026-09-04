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
- `internal/settings` — `settings.yaml`, personal display defaults kept
  separate from `enodia.yaml` (DECISIONS.md D19). Same resolution pattern
  as config (`internal/config/paths.go`): `--settings`, `$ENODIA_SETTINGS`,
  `./enodia.settings.{yaml,yml}`, `./.enodia.settings.{yaml,yml}`,
  `$XDG_CONFIG_HOME/enodia/settings.{yaml,yml}`,
  `/etc/enodia/settings.{yaml,yml}` (`.yml` is checked too, both here and
  in `enodia.yaml`'s own search — equally common in the wild, `.yaml` wins
  ties at the same location, location still beats extension) — but unlike
  config, nothing found is not an error (`settings.Resolve` falls back to
  all-built-in defaults). `render.default_view` applies to
  `check`'s `--view` whenever the flag itself wasn't passed
  (`cmd.Flags().Changed("view")`, not just "is it the zero value", since
  the flag's own cobra default is already "compact"); `html.view` does the
  same for `export --format html`, which also gained its own `--view` flag
  independent of `check`'s
- `html.assets: inline|cdn` — `inline` (default) is byte-for-byte today's
  original fully offline single file (verified: zero `http(s)://` or
  `<script` in output); `cdn` instead loads Bootstrap/Bootswatch and
  renders a visible in-page warning that it needs internet access — not
  just a CLI-side note (skipped for `html.theme: none`, see below, since
  that mode loads nothing). `html.theme` is `none` (no stylesheet at all —
  the markup still carries Bootstrap/RowTone classes, for embedding into a
  page that already loads its own Bootstrap), `default` (plain Bootstrap,
  pinned to `bootstrapVersion`), or one of Bootswatch's 26 real themes
  (pinned to `bootswatchVersion` — kept equal to `bootstrapVersion` since
  Bootswatch tags a release for every Bootstrap release; both bumped to
  5.3.8 together after a live bug: the initially-pinned 5.3.3 predates the
  "brite" theme entirely, 404ing it, and there never was a "default" folder
  in bootswatch's own package at any version — bootswatch.com's site just
  links "Default" straight to plain Bootstrap, which is what `ThemeDefault`
  now actually does instead of guessing a nonexistent bootswatch path).
  Empty `html.theme` resolves to `default`. The resolved theme is baked in
  as both the page's initial stylesheet *and* the fallback target its own
  inline theme-picker script resets to when a viewer's stored
  `localStorage` choice is missing or names an unrecognised theme — an
  operator who set `html.theme: lumen` gets reports that always settle
  back on lumen, never on a hardcoded name unrelated to what they
  configured. `html.cdn` picks the CDN(s): empty/`auto` (default) races
  jsdelivr and cdnjs — both mirror the identical Bootstrap/Bootswatch
  files — with a `HEAD` request each via `Promise.any` and uses whichever
  answers first, so one CDN being blocked or slow on a given network
  doesn't take styling down with it; `jsdelivr` or `cdnjs` pins one
  explicitly (no race, a plain synchronous `<link>`, exactly like before
  racing existed). The very first paint (and anyone with JavaScript
  disabled) always sees jsdelivr's URL — racing only ever *upgrades* the
  stylesheet after the fact, it never delays or changes the initial
  render. Assets/theme/cdn are settings.yaml-only (no CLI flag): D19 treats
  them as a once-per-operator default, not a per-export choice
- `fleet` view gained a STATUS column (grouped alongside PRODUCT/VERSION,
  not folded into a shared bucket — two failed instances with different
  ErrorKinds are different operational situations) built straight from
  `Observation.OK()`/`ErrorKind`, not Assessments (D7) — "table of versions
  + which are up" is this view now, not a separate one
- CDN-mode row highlighting — every view function now also returns a
  `RowTone` per row (`ToneGood`/`ToneInfo`/`ToneWarn`/`ToneBad`, or
  `ToneNone`), which CDN-mode HTML maps to Bootstrap's own standardised
  contextual table classes (`table-success`/`-info`/`-warning`/`-danger`)
  — the same class names carry the right color in every Bootswatch theme,
  so a chosen theme's own red/yellow/green apply, not a hardcoded hex enodia
  would otherwise have to pick and maintain per theme. `compact` tones by
  `OverallSeverity()`; `lifecycle`/`drift` deliberately tone by their own
  axis's severity (`LifecycleSeverity`/`PatchSeverity`), not the overall
  one, so a lifecycle row is red because *its* lifecycle boundary is
  critical, not because an unrelated branch finding was worse; `fleet`
  tones ToneGood/ToneBad only, straight from `Observation.OK()` — a fact,
  never a policy `Severity` (D7), even though it drives the same visual
  vocabulary. Inline mode ignores tones entirely (no Bootstrap loaded to
  give the classes meaning); `Table` (plain text) ignores them too.
- Tests on recorded fixtures, offline, `-race` clean; every new probe
  live-verified against a real instance (Docker or the user's own
  production) before being written, not just against hand-built fixtures

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
