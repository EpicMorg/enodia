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
- `.deb`/`.rpm` packages (linux/amd64+arm64 only — meaningless for darwin/
  windows) via `.goreleaser.yaml`'s `nfpms:`. nfpm is a pure-Go package
  builder, not a wrapper around `dpkg-deb`/`rpmbuild`, so nothing extra
  needs installing anywhere this runs. Binary at `/usr/bin/enodia`; an
  empty, correctly-permissioned `/etc/enodia/` is created for
  `enodia.yaml`/`settings.yaml`/`credentials.yaml`, but the package never
  writes a config into it — a missing `enodia.yaml` staying a loud error
  (`internal/config.Locate`) matters more than an out-of-the-box "just
  works" that could paper over the wrong file being picked up. Verified
  with a real snapshot build: `dpkg-deb -c`/`rpm2cpio | cpio -tv` both show
  exactly those two paths with the right permissions, and `dist/
  artifacts.json` tags them `"Linux Package"` — the same artifact class as
  archives/checksums, so they're published to the GitHub Release
  automatically, no separate upload config needed. `develop.yml`/`pr.yml`
  gained four more `actions/upload-artifact` steps (amd64/arm64 × deb/rpm)
  for the same reason every other platform already gets its own artifact
- Rootless packages — `build/nfpm/preinstall.sh` creates a dedicated
  `enodia` system user/group at a fixed uid/gid `1337` (idempotent via
  `getent`; the id is pinned rather than left to the distro's next free
  system id so numeric ownership matches across every machine the package
  lands on, `build/docker/Dockerfile`'s image included — useful for a
  host-side `chown 1337:1337` on a bind-mounted volume with no name lookup
  needed), `postinstall.sh` chowns `/etc/enodia` (`root:enodia`, `0750`)
  and the two new empty directories `/opt/enodia`/`/var/enodia`
  (`enodia:enodia`, `0750`) to it — nothing in this codebase actually
  hardcodes those last two paths today (the resolver cache uses
  `os.UserCacheDir()` instead), they're placeholder FHS spots for whatever
  a future systemd-managed `enodia serve` needs to write. Ownership is set
  in `postinstall`, not baked into `nfpms.contents`' own
  `file_info.owner/group`, because a `.deb`'s payload carries numeric UIDs
  resolved at *build* time and the `enodia` user only exists on whatever
  machine actually installs the package. Verified with a real snapshot
  build against both formats: `dpkg-deb -e`/`rpm -qp --scripts` show the
  exact scripts, `dpkg-deb -c`/`rpm2cpio | cpio -tv` show all three
  directories at the right modes, and a real `apt install`/`dnf install`
  inside fresh `debian:trixie`/`fedora:latest` containers confirms
  `enodia:x:1337:1337:...` and matching directory ownership end to end
- Man pages — `cmd/enodia/genman_cmd.go`'s hidden `enodia gen-man <dir>`
  subcommand wraps `cobra/doc`'s `GenManTree` (a subpackage of the already-
  approved `cobra` dependency, though it does pull three new indirect
  dependencies of its own for markdown rendering — `go-md2man`,
  `blackfriday`, `go.yaml.in/yaml/v3` — accepted deliberately rather than
  hand-rolling a troff writer). `make man` builds a throwaway host binary,
  runs it, gzips the output into `build/man/` (generated, gitignored, never
  committed); `.goreleaser.yaml`'s `before.hooks` runs it before packaging,
  and `nfpms.contents` maps `build/man/*.1.gz` into `/usr/share/man/man1/`.
  One page per command including subcommands (`enodia-collect.1`,
  `enodia-config-path.1`, etc.) — verified present with the right names in
  both package formats via the same snapshot build
- `install.ps1` — Windows counterpart to `install.sh`, mirroring its logic
  (same repo, same archive naming, same latest/download alias to skip the
  GitHub API's rate limit) for the one OS `install.sh` explicitly declines
  to handle. `install.sh` itself switched its "latest" case from parsing
  `api.github.com/.../releases/latest`'s `tag_name` to the same
  `/releases/latest/download/` alias `build/docker/Dockerfile` already
  uses — one fewer API call, no rate-limit exposure, and no `curl`+`grep`+
  `sed` chain to keep in sync with GitHub's JSON shape
- `build/docker/Dockerfile` — a second, alternate runtime image on the
  user's own `ghcr.io/epicmorg/debian:trixie-light` base, installing the
  released `.deb` via `apt` instead of copying a raw binary into `scratch`
  the way the repo-root `Dockerfile` (goreleaser's own `ghcr.io/epicmorg/
  enodia` image) does — a full Debian userland on purpose, for whatever
  the house image already brings. `/etc/enodia` and `/opt/enodia` (the
  latter for exported reports/inventory, not created by the package
  itself) are both declared as volumes. `ENODIA_VERSION=latest` resolves
  through GitHub's own `/releases/latest/download/` alias, needing no
  version string at all; an exact tag can be passed instead. Verified as
  much as this environment allows: the `apt-get install ./local.deb` step
  itself against a real snapshot-built package inside the real base image
  (binary and both directories landed correctly, `enodia --help` ran), and
  the URL-construction shell logic standalone for both the `latest` and
  pinned-version cases — not the actual `curl` download from a live
  release, since none exists yet and this environment's own build
  sandbox can't reach a local test server to fake one convincingly
- Windows resource embedding — `build/windows/` (icon, version-info `.rc`
  template, manifest) compiled by `make windows-resources`/`windows-exe`
  into `cmd/enodia/resource_windows_{amd64,386,arm64}.syso`. amd64/386 use
  mingw-w64's windres (x86_64/i686 flavors, an `apt install mingw-w64`
  away); arm64 uses llvm-mingw's `aarch64-w64-mingw32-windres` instead,
  since Debian's mingw-w64 package ships none — discovered via
  `$LLVM_MINGW_DIR/llvm-mingw-*-ucrt-ubuntu-22.04-x86_64/bin/` (wildcarded
  because that path's own date stamp changes with every toolchain
  refresh), which `ghcr.io/epicmorg/debian:trixie-develop` sets. All three are
  checked independently; missing any one is a skip, never a failure for
  the others. Verified end-to-end against the real image (`docker run -v
  $PWD:/workspace ... make windows-resources` and a windows/arm64 build):
  real multi-size icon and version block land in a real ARM64 PE32+ `.exe`,
  console subsystem kept intact (no `-H=windowsgui` — that's for GUI apps,
  and would hide this CLI's own stdout/stderr). windows/arm (32-bit
  "armv7") has no equivalent and never will: confirmed live that Go itself
  has no such build target at all (`go tool dist list` omits it, and
  building one fails with "unsupported GOOS/GOARCH pair") — there is no
  binary of that shape to embed a resource into, independent of windres.
  Wired into real releases too, not just local runs — see the CI entry
  below: `release.yml`'s job now runs inside the same image, so tagged
  releases get the arm64 icon automatically
- `make dist` — `linux/{amd64,arm64}`, `darwin/{amd64,arm64}`,
  `windows/{amd64,arm64,386}`, same `-ldflags` as `make enodia`, all three
  windows targets picking up the icon/version resource via
  `windows-resources` when its toolchain is available. `.goreleaser.yaml`
  gained a second build (`enodia-windows-386`, since Go never supported
  darwin/386 — it can't share enodia's goarch list) folded into the same
  archives. Verified with a real `goreleaser check` and a
  `--snapshot --clean --skip=docker,sign,publish` run, not just `make
  dist`: all seven binaries have the right file type (ELF/Mach-O/
  PE32/PE32+). macOS ships
  unsigned — no Apple Developer Program membership needed for this; the
  project's existing cosign signature over `checksums.txt` (D17) already
  gives independent supply-chain verification for every platform,
  Apple-signed or not. A first Gatekeeper launch will still warn
  "unidentified developer" (routine for curl/browser-downloaded CLI tools,
  cleared via `xattr -d com.apple.quarantine` or right-click → Open) — not
  something to design around
- `internal/settings` — `settings.yaml`, personal display defaults kept
  separate from `enodia.yaml` (DECISIONS.md D19). Same resolution pattern
  as config (`internal/config/paths.go`): `--settings`, `$ENODIA_SETTINGS`,
  `./enodia.settings.{yaml,yml}`, then a bare `./settings.{yaml,yml}` (the
  `enodia.`-prefixed form wins if both exist — added after a real user
  expected the plain name next to the binary to just work, and it didn't),
  `./.enodia.settings.{yaml,yml}`, `$XDG_CONFIG_HOME/enodia/settings.{yaml,yml}`,
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
- CI: `release.yml`'s job now runs inside `ghcr.io/epicmorg/debian:trixie-develop`
  (`container:`, not a `docker run` step) — the whole point being that
  image already carries Go, mingw-w64, and llvm-mingw, so real tagged
  releases now get the windows/arm64 icon too, with nothing left to
  install except a bare `docker` CLI + buildx plugin (the image ships
  neither). This is *not* docker-in-docker: the job's own container
  bind-mounts the runner's existing docker socket
  (`-v /var/run/docker.sock:/var/run/docker.sock`) and talks to it as a
  sibling container — confirmed live, no `--privileged` needed, since the
  image already runs as root by default. Release trigger is a tag matching
  `*.*.*+*`, plus an explicit `git merge-base --is-ancestor` step
  confirming the tagged commit is actually reachable from `origin/master`
  — the tag-shape filter alone can't express "and it came from master".
  Tags are `MAJOR.MINOR.PATCH+BUILD`, no `v` prefix (e.g. `1.2.3+4`), not
  the originally-requested `X.Y.Z.B`: confirmed live that goreleaser
  hard-fails ("invalid semantic version") on a literal four-dot tag unless
  `--skip=validate`, which also disables its dirty-worktree check — not
  something to run permanently. `+BUILD` is valid semver build metadata
  and parses cleanly with no flags. Makefile's `VERSION_CSV` (the Windows
  resource's FILEVERSION) now extracts all four numbers from this shape.
  One thing `+` breaks that `.` wouldn't have: Docker tag syntax flatly
  disallows it (confirmed: `docker tag foo:1.2.3+4` — "invalid reference
  format") — `.goreleaser.yaml`'s `dockers_v2.tags` now applies
  `{{ replace .Version "+" "-" }}` before it ever reaches a tag; the OCI
  `image.version` annotation keeps the raw `+4` since annotations have no
  such restriction. Verified as much of this locally as is safe without
  touching the real repo/registry: the container image's docker-socket
  mount, apt-installing `docker.io`/`docker-buildx` inside it, goreleaser
  parsing `1.2.3+4`/`+4` tags cleanly, `VERSION_CSV` extracting all four
  parts, and the `replace` template function itself (proven via a real
  local build+archive run) — not an actual push to `ghcr.io/epicmorg/enodia`
  or a real GitHub release, since faking that needs real credentials
  against their live infrastructure
- CI: `develop.yml` (manual, `workflow_dispatch` only) and `pr.yml`
  (automatic on `pull_request`) — the same `ghcr.io/epicmorg/debian:trixie-develop`
  container as `release.yml`, `goreleaser release --snapshot --clean
  --skip=docker,sign` (no docker CLI needed at all here, since neither
  ever touches GHCR or cosign), each of the 7 archives plus `checksums.txt`
  uploaded as its own separate `actions/upload-artifact` — one artifact
  per platform, not one shared name across a multi-file `path:`, which
  bundles everything into a single zip a per-platform download shouldn't
  have to unpack. `develop.yml` is
  deliberately never triggered by a push: pulling a ~5GB image on every
  commit to `develop` would make ordinary iteration there unworkable;
  `pr.yml` accepts that same cost automatically because a PR is a
  deliberate review checkpoint, not routine commit-by-commit work.
  Verified locally: the exact `goreleaser` invocation both workflows run
  produces all 7 archives + `checksums.txt` with no snapshot-only skip
  needed beyond `docker,sign`; both files pass `actionlint`

## Later

- CVE correlation via OSV.dev — investigated twice, deferred both times;
  revisit only if a workable data source appears — see DECISIONS.md D18
  for exactly what was tried and why it's closed, not just deferred

## Deliberately not planned

- Hosted SaaS
- A refresh button that triggers collection
- Any growth of the generic probe's vocabulary
- Built-in authentication for `serve`
