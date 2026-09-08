# Roadmap

Not dates. Order of work, and what each step unblocks.

## Done

- `internal/probe` — interface, HTTP helper, TLS settings, typed errors
- `internal/probe` — 54 products: apache (httpd alias), the atlassian
  family (jira/confluence/bitbucket/bamboo), artifactory,
  bitwarden/vaultwarden, clickhouse, elasticsearch, esxi, forgejo,
  generic, gitlab, grafana, graylog, haproxy, harbor, jaeger, jellyfin,
  jenkins, keycloak, kibana, kitsu, logstash, mattermost, mongodb,
  mysql, nextcloud, nexus, nginx, oauth2-proxy, opensearch, owncast,
  perforce-swarm, pgadmin, phpmyadmin, portainer, postgres_exporter,
  postgresql, proftpd, redis, routeros, sonarqube, ssh, teamcity,
  testrail, traefik, vault, vcenter, wordpress, youtrack, zabbix, zou
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
  gained four more `actions/upload-artifact` steps (amd64/arm64 × deb/rpm,
  later eight once `.apk` and `.pkg.tar.zst` joined them) for the same
  reason every other platform already gets its own artifact
- Rootless packages — `build/nfpm/preinstall.sh` creates a dedicated
  `enodia` system user/group at a fixed uid/gid `1337` (idempotent; the id
  is pinned rather than left to the distro's next free system id so
  numeric ownership matches across every machine the package lands on,
  `build/docker/Dockerfile`'s image included — useful for a host-side
  `chown 1337:1337` on a bind-mounted volume with no name lookup needed),
  `postinstall.sh` chowns `/etc/enodia` (`root:enodia`, `0750`) and the two
  new empty directories `/opt/enodia`/`/var/enodia` (`enodia:enodia`,
  `0750`) to it — nothing in this codebase actually hardcodes those last
  two paths today (the resolver cache uses `os.UserCacheDir()` instead),
  they're placeholder FHS spots for whatever a future systemd-managed
  `enodia serve` needs to write. Ownership is set in `postinstall`, not
  baked into `nfpms.contents`' own `file_info.owner/group`, because a
  package's payload carries numeric UIDs resolved at *build* time and the
  `enodia` user only exists on whatever machine actually installs it.
  `preinstall.sh` branches on whether `groupadd` exists rather than
  detecting a distro: deb/rpm targets always have GNU shadow-utils
  (`groupadd`/`useradd`), but the `apk` target below is Alpine, whose base
  image ships neither — only busybox's `addgroup`/`adduser`, a different
  flag syntax, and `/sbin/nologin` instead of `/usr/sbin/nologin`. Verified
  with real `apt install`/`dnf install`/`apk add` inside fresh
  `debian:trixie`/`fedora:latest`/`alpine:latest` containers, all three
  landing `enodia:x:1337:1337:...` and matching directory ownership;
  `dpkg-deb -e`/`rpm -qp --scripts` also show the exact scripts verbatim
- `.apk` (Alpine) and `.pkg.tar.zst` (Arch, nfpm's `archlinux` format)
  alongside `.deb`/`.rpm` in the same `nfpms:` block — nfpm already
  supports both, no extra tooling. Arch's base image ships GNU shadow-utils
  (`useradd`/`groupadd`) same as deb/rpm, so `preinstall.sh`'s existing
  branch covers it with no changes; verified live with `pacman -U` inside a
  fresh `archlinux:latest` container — `enodia:x:1337:1337` and correct
  directory ownership land exactly like the other three formats (a harmless
  `SYS_UID_MAX 999` warning from `useradd`, since 1337 is deliberately
  outside the typical system-id range — install still succeeds with the
  requested id). The man pages *are* in the package (confirmed via a raw
  `tar` listing) but the official `archlinux` Docker image doesn't extract
  them on install — its own `/etc/pacman.conf` ships a global `NoExtract =
  usr/share/man/*` for container-image size, unrelated to this package; a
  real Arch install has no such default. `make pkg` wraps the exact
  `goreleaser release --snapshot --clean --skip=docker,sign` invocation CI
  already runs (see below), so all four package formats plus every archive
  land in `dist/` from a single local command, with no tag or CI needed —
  `make dist` deliberately stays a bare `go build` loop with no packaging
  step, since duplicating nfpm's config in Make would just be a second copy
  of `.goreleaser.yaml` to keep in sync
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
- Fixed: `install.ps1` persisted the install dir to the `User` PATH via
  `[Environment]::SetEnvironmentVariable(..., "User")`, but that only
  writes the registry (`HKCU\Environment`) — a shell already running when
  the installer is invoked via `irm ... | iex` never re-reads it, so
  `enodia` stayed "not recognized" in that same window even though the
  install had just "succeeded". Now also patches the invoking process's
  own `$env:Path` directly, so the binary is runnable immediately, no new
  terminal required — the registry write still happens too, for every
  shell opened afterward. Also fixed a minor rough edge while touching
  this: a brand new Windows account with no `User` PATH set yet produced
  a leading empty entry (`;C:\...\enodia`) in the persisted value
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
- Fixed: `parser.cleanRegex` in `enodia.yaml` was silently rejected —
  `probe.ParserSpec` only carried `json:` tags, so `yaml.v3` (with
  `KnownFields(true)`) fell back to the lowercased Go field name with no
  word splitting (`cleanregex`), not the `cleanRegex` docs/DECISIONS.md
  (D3) and docs/CLAUDE.md actually documented. Found by the docs-repo
  agent while writing enodia-docs content, confirmed by decoding a real
  YAML target through `internal/config` in a test. Fixed by adding
  explicit `yaml:` tags to `ParserSpec`, spelled `clean_regex` (snake_case)
  to match every other multi-word key in the schema (`ca_file`,
  `min_version`, `allow_insecure_transport`, ...) rather than inventing a
  lone camelCase exception — D3/CLAUDE.md updated to match. Never shipped
  in a release, so no back-compat concern
- `settings.yaml` also checked next to the running executable, not just
  cwd/XDG/`/etc` — the actual "next to the binary" case, distinct from cwd:
  `install.ps1` puts `enodia.exe` in `%LOCALAPPDATA%\enodia` and adds that
  to PATH, so on Windows especially, cwd at invocation time is essentially
  never the install directory (the whole point of PATH is that it stops
  mattering). `internal/settings/paths.go`'s new `executableDir()` resolves
  `os.Executable()` through `filepath.EvalSymlinks` first, so a PATH shim
  (e.g. a version manager) doesn't make settings.yaml appear to live
  somewhere the real binary never runs from. Precedence: cwd forms still
  win first, then the executable's directory, then XDG, then `/etc/enodia`.
  Deliberately scoped to `settings.yaml` only — `enodia.yaml` carries
  credentials and does not gain this step, so a shared/portable install
  directory can't get a config file silently picked up from it
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
- Fixed, in two passes: an unreachable target's `lifecycle`/`drift` rows
  read `ToneGood` (green) even though every cell was a dash —
  `PatchUnknown`/`LifecycleUnknown` both leave their axis's `Severity` at
  the zero value (`SeverityNone`), which `severityTone`'s default case
  maps to green, the same as an axis that was actually checked and found
  fine. First pass: both views tone any `PatchUnknown`/`LifecycleUnknown`
  row `ToneInfo` (blue) — better than green, but still wrong for a
  *reachable* target whose `Reason` is `cycle_unmatched` (the vendor's
  calendar just doesn't track that cycle) or `resolver_error`: those
  aren't the same anomaly as a target that never answered at all, and
  painting them the same blue buried a real, actionable gap (a
  since-live example: TeamCity instances answering fine, with a real
  observed version, whose cycle just isn't in endoflife.date) under the
  same color as "this is actually broken". Second pass: `compact` had the
  opposite problem — `probe_failed` rows blended into ordinary
  `SeverityWarn` ones (both floor at the same severity via
  `ReasonSeverity`), so an actual 502 or wrong-service-entirely target
  read no differently from a real policy warning and got lost among them.
  Landed as `isUnreachableAnomaly` (true only for `Reason: probe_failed`,
  and only when policy hasn't escalated it to `SeverityFail` via
  `--fail-on=reason:probe_failed` — that override still renders Bad, on
  purpose) plus `unknownAxisTone`, used by all three views:
  `lifecycle`/`drift` tone `PatchUnknown`/`LifecycleUnknown` via
  `unknownAxisTone` (`ToneInfo` for a genuine anomaly, else the axis's own
  `ReasonSeverity` tone — `ToneWarn` for `cycle_unmatched`); `compact`
  tones by `OverallSeverity()` as before, except a genuine anomaly always
  renders `ToneInfo` regardless of what severity math alone would pick
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
- HTML report footer now also links `enodia.sh` and `docs.enodia.sh`
  (alongside the existing GitHub link), in both inline and CDN mode —
  plain `<a href>`s, not a resource fetch, so this doesn't touch the
  inline-mode offline guarantee (D19's "zero `http(s)://` or `<script`"
  check is specifically about *loaded* resources, not inert hyperlink
  text — the GitHub credit link already established that precedent).
  Also gained a favicon: inline mode embeds `enodia.sh`'s
  `apple-touch-icon.png` (180x180, ~8.6KB base64) as a `data:` URI rather
  than `enodia.sh/favicon.ico` itself — that `.ico` is a 9-size,
  381KB multi-resolution set that would add ~508KB of base64 to every
  single generated report, which the tool's whole "one small
  self-contained file" premise doesn't need for something as
  inconsequential as a tab icon. CDN mode instead links both live
  `https://enodia.sh` icons directly (`<link rel="icon">` /
  `rel="apple-touch-icon"`) — that mode already needs internet access to
  render at all, so there's no offline guarantee to protect and no reason
  to bloat the page for an icon the browser can just fetch itself
- `settings.yaml` gained `export.default_format`, used by `export`
  whenever `--format` itself is not passed on the command line (built-in
  default stays `json` either way) — `./enodia export > report.html`
  previously always wrote JSON regardless of the file's name, since
  nothing about `settings.yaml`'s `html.*` block was ever consulted
  outside the `--format html` branch. Same precedence rule `check`'s
  `render.default_view` already established: `cmd.Flags().Changed(
  "format")`, not "is the value still the flag's own default", so an
  explicit `--format json` still beats a `settings.yaml` that says
  `html`. Not enum-validated in `internal/settings` — an unrecognised
  value surfaces through the exact same `format %q is not supported`
  check `--format` itself already goes through, no second definition of
  "valid" to keep in sync
- `install.sh` now falls back to `$PREFIX/bin` when the target install
  directory isn't writable and there's no *working* `sudo` to retry
  with — Termux (and other sandboxed userland-prefix environments) ship
  neither a writable `/usr/local/bin` nor a real `sudo`, so the script
  used to hard-fail. Kept generic on purpose, no name-based "is this
  Termux" branch: `$PREFIX` is that environment's own "where my stuff
  goes" variable. `uname`-based OS/arch detection is untouched — Termux
  reports `Linux`/`aarch64` like any other Android-on-ARM device.
  **Fixed on first real-device use via `get.enodia.sh/unix`:** the
  original check was `command -v sudo` — a present binary, not a working
  one. Termux's own optional `sudo` *package* sits on `PATH` and fails
  outright on an unrooted device (`No superuser binary detected. Are you
  rooted?`, exit non-zero), so the script picked the "retry with sudo"
  branch anyway and then hard-failed on that error instead of ever
  reaching the `$PREFIX/bin` fallback. Now actually runs `sudo install`
  and only counts it as done if it exits 0; any other outcome — missing
  entirely or present-but-unusable — falls through to `$PREFIX/bin` the
  same way
- `enodia_android_arm64` — a real Termux user hit the actual next problem
  right after the `$PREFIX/bin` fix above: even installed, the
  `linux_arm64` binary wouldn't exec at all on Termux, Bionic's linker
  rejecting it with `"has unexpected e_type: 2"` (`ET_EXEC`; Android has
  required PIE/`ET_DYN` since Lollipop). A new goreleaser build
  (`GOOS: android`, `GOARCH: arm64`) and archive fix this properly — see
  DECISIONS.md D20 for why a straight `-buildmode=pie` on the existing
  `linux` build was tried and rejected (breaks Alpine/musl) in favor of
  Go's real `android` target, and why Termux detection uses
  `$TERMUX_VERSION` rather than the `$PREFIX` already used for the
  install-directory fallback. `install.sh` picks the right archive
  automatically; no change needed to how anyone invokes it
- Found on the same real device right after that fix, on a **rooted**
  phone specifically: the correct `android_arm64` binary still failed to
  exec as the ordinary Termux user (worked fine under `su` + a full
  path) — matches a known, open, already-being-fixed upstream bug,
  `termux-exec`'s own linker-exemption logic not recognizing Magisk/
  KernelSU/`run-as`/ADB process contexts
  ([termux-exec#40](https://github.com/termux/termux-exec/issues/40)).
  Nothing changed here: this is upstream's own bug in a process-context
  check, not something this project's build or `install.sh` can route
  around — see DECISIONS.md D20's "Revisited". Expected to not reproduce
  on a non-rooted device at all
- The container image now also pushes to `docker.io/epicmorg/enodia` and
  Quay, not GHCR alone — same tags, same multi-arch manifest, three
  `docker/login-action` steps in `release.yml` ahead of the one
  `goreleaser-action` run. Unlike GHCR (D17: piggybacks on `GITHUB_TOKEN`,
  nothing to mint or leak), these use real org-level secrets this repo
  only consumes. See DECISIONS.md D17's "Revisited" for the credential
  names and why `QUAY_SERVER_URL` is templated in, not hardcoded as
  `quay.io`. Verified live without pushing: a real local multi-arch
  `docker buildx` build (`goreleaser release --snapshot --skip=sign`)
  produced correctly tagged manifests for all three registries
- Fixed: `bamboo` was registered with `resolver: ""` (no lifecycle data
  source) in `registry.go`, apparently because it had no endoflife.date
  entry when that line was written. It does now — confirmed live,
  `https://endoflife.date/api/bamboo.json` resolves real cycle/eol data —
  so it now gets the same `DefaultResolver` wiring jira/confluence/
  bitbucket already have
- `zabbix` probe — `apiinfo.version`, the one JSON-RPC method Zabbix's API
  documents as needing no authentication. Confirmed live against a
  real, internet-facing Zabbix frontend: POST only (a bare GET answers
  412, not a version), plain `Content-Type: application/json` accepted
  (not just the API reference's own `application/json-rpc`). `FetchHTTP`
  gained a `Request.Body []byte` field for this — the first probe needing
  a request body, everything before it being GET-with-headers
- `youtrack` probe — `GET /api/config?fields=version`. Confirmed live
  against a real, internet-facing instance: needs no credentials, and an
  anonymous caller asking for extra fields (buildDate, edition, ...) just
  gets them silently dropped — only `version` comes back
- `nginx` probe — the `Server` response header, the only anonymous version
  source nginx has at all (`/stub_status` gives connection counters, never
  a version). Confirmed live against real `nginx:1.27.4` containers: any
  status code (301/403/404/50x, not just 200) still carries it, but
  `server_tokens off` — common hardening — stamps a bare `Server: nginx`
  with no version, which this probe cannot work around; classified as
  `ErrNotSupported` (decided explicitly, not assumed: this is confirmed
  nginx, just a deployment whose own config makes the version
  unavailable, the same sense postgres's/mysql's unsupported-auth-method
  cases already stretch that sentinel to cover)
- `oauth2-proxy` probe — no JSON version endpoint exists; reads the
  version stamped in `/oauth2/sign_in`'s default footer instead (the
  sign-in page is inherently public). Confirmed live against a real
  oauth2-proxy/oauth2-proxy container. No `DefaultResolver`:
  endoflife.date has no calendar for it today — the user intends to
  submit one upstream later, alongside teamcity and perforce-swarm, which
  are in the same boat. The `--footer` flag can replace or hide ("-")
  that line entirely — same shape of problem as nginx's `server_tokens
  off` above, same `ErrNotSupported` classification
- `traefik` probe — `GET /api/version`. Confirmed live against a real
  `traefik:v3.1` container: needs no credentials under
  `--api.insecure=true`; a stock instance (neither `--api` nor
  `--api.insecure` set — the default) answers plain 404 here, already
  covered by `FetchHTTP`'s existing 404-is-`ErrNotSupported` handling, no
  special-casing needed. `AuthBasic` accepted for the documented "secure"
  deployment shape (API router wired behind Traefik's own
  BasicAuth/DigestAuth middleware)
- `harbor` probe — `GET /api/v2.0/systeminfo`. Confirmed live against a
  real goharbor/harbor v2.12.2 stack (installed via the official
  docker-compose installer, not a single container): `harbor_version`
  comes back with no credentials, and bad/fabricated Basic credentials
  are silently treated as anonymous rather than 401. Worth a specific
  callout: reading Harbor's own source turned up a same-day upstream
  commit on `main` (unreleased at the time of writing) that gates
  `harbor_version` behind `sc.IsAuthenticated()` — every currently
  released version still returns it anonymously, but this will stop
  working once that change ships in a release. `AuthBasic` is already
  offered so a configured credential keeps working either way; the
  missing-field case is `ErrNotSupported`, same family as nginx/
  oauth2-proxy/traefik above
- `postgres_exporter` probe — the `postgres_exporter_build_info` gauge off
  `/metrics`, the same prometheus/common "version collector" pattern every
  Prometheus exporter in this ecosystem uses (constant `1`, version in a
  label). Confirmed live against a real prometheuscommunity/
  postgres-exporter container: needs no credentials by default, and
  answers even with an unreachable target Postgres — `build_info`
  describes the exporter binary, not the database it scrapes (unrelated
  to the existing `postgres` probe, which talks to the database
  directly). No endoflife.date entry (this isn't a product with a
  lifecycle policy) — `DefaultResolver` points at GitHub Releases
  (`prometheus-community/postgres_exporter`) instead, the first probe to
  default to that resolver rather than endoflife.date
- `haproxy` probe — the version text in the stats page's own `<h1>`
  heading (`HAProxy version 3.0.27-a2b09cd, released ...`). Confirmed
  live against a real `haproxy:3.0` container: HAProxy sets no `Server`
  header identifying itself at all by default (unlike nginx), and the
  `;csv` stats export was confirmed to carry no version column anywhere
  in its ~140-column header — the HTML stats page is the only anonymous
  surface, and only when `stats enable` is configured at all (off by
  default). `stats auth user:pass` is ordinary HTTP Basic, already
  covered
- `apache` (alias `httpd`) probe — the `Server` response header, the same
  shape of problem as `nginx` above. Confirmed live against real
  `httpd:2.4` containers: default build answers `Apache/2.4.68 (Unix)`;
  `ServerTokens Prod` (Apache's own `server_tokens off` equivalent, same
  `ErrNotSupported` classification) strips it to a bare `Apache`.
  `DefaultResolver` uses endoflife.date's actual slug
  `apache-http-server` directly — both `apache` and `httpd` were
  confirmed to just 301-redirect there
- `clickhouse` probe — runs `SELECT version()` against the HTTP interface
  (port 8123) and reads the bare TabSeparated reply (a single-column,
  single-row result is just the value and a newline — nothing to
  unmarshal). Confirmed live against a real clickhouse/clickhouse-server
  container: recent images require `CLICKHOUSE_PASSWORD` to be set at
  all (no blank default-user password to fall back to, unlike older
  installs) — an unauthenticated request gets a normal 401, already
  ordinary `ErrAuth` via `FetchHTTP`, nothing clickhouse-specific needed.
  The reply is checked against a "looks like a version" pattern before
  being trusted, since a bare-text response has nothing else to
  distinguish a real reply from an unrelated service answering 200 at
  that address
- `mongodb` probe — D10 in its purest new form since mysql: runs the
  `buildInfo` command over the raw wire protocol (OP_MSG) and reads its
  "version" field, hand-encoding the one BSON command document it sends
  and decoding just enough of the reply to find that field — no client
  library, same level of effort as mysql.go's handshake parser and
  redis.go's RESP codec. Confirmed live against two real mongo:7
  containers, one with no access control at all and one with `--auth`
  and a root user configured: both returned the exact same full
  buildInfo document with zero credentials sent — `buildInfo` is one of
  the small set of commands MongoDB always answers before authentication
- `nexus` (Sonatype Nexus Repository) probe — the `Server` response
  header, same shape as `nginx`/`apache` above, but read off the
  purpose-built anonymous status endpoint (`/service/rest/v1/status`, a
  fast empty-bodied health check) rather than `/`. Confirmed live
  against a real sonatype/nexus3 container: `Nexus/3.96.0-09
  (COMMUNITY)` on that endpoint, the portal page, and a 401 challenge
  from a different, actually-protected endpoint alike. Unlike nginx/
  Apache, no config toggle to strip this to a bare `Nexus` is documented
  or was found, but the parser degrades to `ErrNotSupported` rather than
  assuming it can never happen
- `wordpress` probe — tries the RSS feed's `<generator>` line
  (`/?feed=rss2`, the query-string form that works with or without pretty
  permalinks — confirmed live: a stock install without permalinks
  configured 404s on `/feed/` but answers this form) before falling back
  to the homepage's `<meta name="generator">` tag. The feed is tried
  first because reading wp-includes/default-filters.php's actual hook
  registrations confirmed it survives the single most common hardening
  step (`remove_action('wp_head', 'wp_generator')` only touches the
  homepage tag, since feeds register `the_generator()` on their own
  separate hooks) — this project's first probe that tries a second
  anonymous endpoint when the first one comes back without what it
  needs, rather than failing straight to `ErrNotSupported`
- `phpmyadmin` probe — the version field inside the login page's own
  `CommonParams.setAll({...})` JS bootstrap call, which phpMyAdmin's own
  JS uses for every AJAX request it makes, so it ships on every page —
  no separate version endpoint needed. Confirmed live against a real
  phpmyadmin/phpmyadmin container. A JS object literal with unquoted
  keys, not JSON, so this is a text match rather than a
  `json.Unmarshal`
- `forgejo` probe — `GET /api/v1/version`, the same Gitea-API-compatible
  path Forgejo (a Gitea fork) still ships. Confirmed live against a real
  codeberg.org/forgejo/forgejo container: anonymous by default; a real
  hardening option, `REQUIRE_SIGNIN_VIEW = true`, confirmed live to
  answer 403 on this endpoint too, already ordinary `ErrAuth` via
  `FetchHTTP`'s existing 401-or-403 handling, nothing forgejo-specific
  needed
- `graylog` probe — `GET /api/`, the REST API's own root discovery
  document, confirmed live against a real graylog/graylog container
  (plus the MongoDB and Elasticsearch it depends on) to answer with no
  credentials at all
- `kibana` probe — `GET /api/status`, deliberately unauthenticated by
  design (the official Elastic Helm chart's own readiness/liveness probe
  curls this exact path with no credentials). Confirmed live against a
  real docker.elastic.co/kibana/kibana container (backed by a real
  Elasticsearch): the reply carries the full version even while
  answering 503 ("not ready yet") during startup, so 503 is accepted as
  OK and the body read regardless
- `logstash` probe — `GET /` on Logstash's own HTTP monitoring API (port
  9600, not the Elasticsearch or Kibana ports), which has no built-in
  auth at all — meant to be firewalled off rather than
  credential-protected. Confirmed live against a real
  docker.elastic.co/logstash/logstash container
- `opensearch` probe — `GET /`, the same endpoint and shape as
  `elasticsearch` (OpenSearch is a fork of Elasticsearch 7.10.2 that
  kept it almost unchanged). Confirmed live against real containers of
  both that the one reliable discriminator is
  `version.distribution: "opensearch"`, absent on a genuine
  Elasticsearch reply — each probe now rejects the other product's real
  fixture as `ErrNotSupported` (D9). Found and fixed in passing:
  `elasticsearch.go` had no product check at all before this and would
  have silently reported an OpenSearch cluster's version as
  Elasticsearch's. Security posture confirmed to match
  `elasticsearch`'s exactly: HTTPS + Basic auth required by default
  (`OPENSEARCH_INITIAL_ADMIN_PASSWORD` must be set at all), or fully
  anonymous with the real, documented `DISABLE_SECURITY_PLUGIN=true`
- `routeros` probe — MikroTik's REST API (`GET
  /rest/system/resource`, RouterOS 7.1+). Confirmed live against a real
  CHR (Cloud Hosted Router) VM booted under QEMU (no docker image exists
  for RouterOS): unlike almost everything else in this tree, there is no
  anonymous path at all — this endpoint always 401s without credentials,
  the anonymous webfig login page at `/` carries no version text, and
  even the SSH banner (`SSH-2.0-ROSSSH`) has none either, ruling out the
  banner trick `ssh.go`/`mysql.go` use. `Auth.Required: true`, same
  shape as `keycloak`. `.golangci.yml` gained a `misspell.ignore-rules`
  entry for "routeros" — the linter reads it as a typo of "routers"
- `esxi` probe — the vSphere API's own `RetrieveServiceContent` SOAP
  discovery call (`vim25.go`, a new shared helper). Confirmed live
  against a real, production ESXi 8.0.3 host, no credentials at all:
  `about.apiType` is `"HostAgent"`, `about.version` is the real
  marketing version (`"8.0.3"`, not the coarser `vim25` API schema
  version `vcenter` used to report). D9: `apiType` is checked so a real
  vCenter's identical reply (`apiType=VirtualCenter`) is rejected, not
  silently reported as ESXi
- Fixed: `vcenter.go` had the same D9 gap `elasticsearch.go` had before
  the `opensearch` probe — it read `/sdk/vimServiceVersions.xml`, which
  answers identically for ESXi and vCenter alike, so it could never tell
  the two apart. Switched it to the same `vim25RetrieveAbout` helper
  `esxi` uses, checking `apiType == "VirtualCenter"`. Confirmed live
  against a real, production vCenter 8.0.3 instance — each probe now
  rejects the other's real captured reply as `ErrNotSupported`, both
  directions backed by a live fixture, not one side inferred from
  documentation
- `proftpd` probe — reads the RFC 959 FTP greeting (D10, no client
  library, same family as `ssh`/`mysql`). Read `src/session.c`
  (`pr_session_send_banner`) and confirmed live twice — a real
  production host and a fresh `instantlinux/proftpd` container's
  default config — that the true out-of-the-box default carries no
  version at all (`"ProFTPD Server (<name>) [<address>]"`); it only
  appears if an admin explicitly configures `ServerIdent on "...
  %{version} ..."`, confirmed live too by adding that directive to the
  same container and reading the real substituted banner. So the
  "no version" case is the common one here, not the exception —
  `ErrNotSupported`, same family as `nginx`'s `server_tokens off`, just
  opt-in exposure instead of opt-out hiding
- `jaeger` probe — the query-service (the UI, port 16686) embeds its
  version into `index.html` at build time via search/replace:
  `const JAEGER_VERSION = {"gitCommit":...,"gitVersion":"v1.76.0",...}`,
  a real JSON object literal so it's `json.Unmarshal`ed rather than
  field-by-field regexed. Confirmed live against a real
  jaegertracing/all-in-one container, including that it's a single-page
  app — every path, even a nonexistent one, serves the identical
  `index.html`. Jaeger has no authentication of its own at all;
  deployments needing access control put something in front of it —
  the user's own instance sits behind oauth2-proxy for exactly this
  reason. A target behind such a gateway answers with the gateway's own
  login page instead of Jaeger's HTML, which this probe (like every
  probe in this tree) cannot complete — the same shape of gap D22 found
  for Redmine's form login, just imposed by the deployment rather than
  the product; it surfaces as this probe's ordinary "no JAEGER_VERSION
  found" `ErrNotSupported`, nothing gateway-specific needed
- GitHub Releases wired up as `DefaultResolver` for six probes that had
  none at all: `bitwarden` (`bitwarden/server`), `jellyfin`
  (`jellyfin/jellyfin`), `oauth2-proxy` (`oauth2-proxy/oauth2-proxy`),
  `owncast` (`owncast/owncast`), `portainer` (`portainer/portainer`),
  `vaultwarden` (`dani-garcia/vaultwarden`) — the mechanism itself
  already existed (`internal/resolver/github.go`, used by
  `postgres_exporter` since it was added) and just needed pointing at
  the right repos, each confirmed live via the GitHub API to actually
  exist and carry releases. "Latest version" only, same as
  `postgres_exporter` — no eol/support/lts, GitHub has no opinion on a
  project's lifecycle policy. Bitwarden and Vaultwarden keep separate
  repos deliberately: Vaultwarden is an independent Rust
  reimplementation, not a fork, with its own version numbering that
  must never resolve against `bitwarden/server`'s tags.
  `bitwardenFamilyProbe` gained a `resolver ResolverRef` field per
  instance to let the two diverge (previously both were hardcoded to
  none). Considered and passed on for now: `endoflife.ai`, a
  third-party aggregator that re-publishes endoflife.date plus its own
  additional coverage — checked live via its real (not just advertised)
  API against every product this project is missing from endoflife.date
  itself; it already covers `teamcity` and `bamboo`, but `teamcity`'s
  entry there carries `eol_date: null` (version tracking with no real
  lifecycle judgment), and it has nothing at all for `jellyfin`,
  `owncast`, `portainer`, `vaultwarden`, `oauth2-proxy`, `testrail`,
  `zou`, or `perforce-swarm` — no coverage advantage over GitHub
  Releases for any product actually blocked on this today
- `zou` and `kitsu` split into two distinct products (previously "zou"
  with "kitsu" as a mere spelling alias) so each can carry its own
  resolver: confirmed live that `cgwire/zou` publishes bare git tags
  only (`v1.0.70` latest), no GitHub Releases objects at all — this
  project's GitHub Releases resolver reads the Releases API, so it
  finds nothing there today, and `product: zou` stays resolver-less
  rather than borrow a different component's numbers. `cgwire/kitsu`
  (the Vue.js UI Zou serves — confirmed live, no version endpoint of
  its own) has real Releases (`v1.0.59` latest) and is what a
  deployment actually named "kitsu" in config strategically tracks
  anyway. `zouProbe` became `zouFamilyProbe{product, summary,
  resolver}`, the same shape as `bitwardenFamilyProbe`
- `pgadmin` probe — decodes the `?ver=NNNNN` cache-busting query string
  pgAdmin appends to every static asset on its own login page (anonymous
  by design — it has to render before any session exists). Confirmed
  against a real dpage/pgadmin4 container, both the live page and its
  own source (`version.py`): `NNNNN` is `APP_VERSION_INT`, documented
  there as `[X]XYYZZ` (release/revision/suffix) — `91700` decodes to
  release 9, revision 17, suffix 00 (GA), matching the real version
  exactly. No `DefaultResolver`: endoflife.date has no pgadmin calendar,
  and pgadmin-org/pgadmin4's own GitHub tags use the shape `REL-9_17` —
  internal/version's numeric-spine extraction would read that as bare
  `9`, losing the revision, so wiring the GitHub Releases resolver here
  today would compare against a silently wrong reference rather than no
  reference at all

## Next

Empty: every product that was tracked here across this project's probe
build-out has landed in Done above. Add new entries as new probes get
requested.

## Later

- CVE correlation via OSV.dev — investigated twice, deferred both times;
  revisit only if a workable data source appears — see DECISIONS.md D18
  for exactly what was tried and why it's closed, not just deferred
- `kafka` probe — the wire protocol's entire anonymous surface
  (`ApiVersionsRequest`) is a list of per-API version-number ranges, no
  software version string anywhere — confirmed live against a real
  broker. Blocked pending JMX support (a materially different transport:
  RMI, its own port, off by default), a new kind of probe this project
  doesn't have yet — see DECISIONS.md D21 for what was tried and why an
  ApiVersions-based guess was rejected, not just deferred
- `redmine` probe — nowhere anonymous discloses the version at all
  (confirmed live: not the homepage, not headers, not the Atom feeds'
  own `<generator>` tag, which — unlike `wordpress`'s — carries no
  version attribute). The one page that does, `/admin/info`, needs a
  session cookie from an actual form login with a CSRF token, which no
  existing `AuthKind` represents and no probe in this tree does today —
  see DECISIONS.md D22 for what was tried and why HTTP Basic against
  that page doesn't work either
- `android/amd64`, `android/386`, `android/arm` — Go hard-requires cgo
  against an Android NDK cross-compiler for these three (confirmed live;
  only `android/arm64` supports pure internal linking), and this
  project's build image carries no NDK today. Revisit if/when the shared
  `ghcr.io/epicmorg/debian:trixie-develop` image gains one (same pattern
  as `mingw-w64`/`llvm-mingw` for the Windows builds) — see DECISIONS.md
  D20. Low urgency: `arm64` alone covers essentially every real Android
  device in current use

## Deliberately not planned

- Hosted SaaS
- A refresh button that triggers collection
- Any growth of the generic probe's vocabulary
- Built-in authentication for `serve`
