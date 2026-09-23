# Changelog

Notable changes to enodia, release by release. Tags follow this project's own
`MAJOR.MINOR.PATCH+BUILD` scheme, no `v` prefix (see `docs/DECISIONS.md` D17);
`+BUILD` is semver build metadata, used only for a rebuild with no functional
change, not to sidestep a real version bump. Full reasoning behind any change
below lives in `docs/DECISIONS.md`, referenced by its `D`-number.

## [2.0.0+0] — 2026-09-23

A major version for a major feature, not for a break: CVE correlation is
the first evaluation axis that isn't about lifecycle. Existing
`enodia.yaml`, `settings.yaml` and inventory files work unchanged — the
new `cve:` block is optional, and a config without it behaves exactly as
1.2 did.

### Added

- **CVE correlation** against two local databases, BDU ФСТЭК and NIST NVD
  (D30, D31). enodia never downloads them: the operator fetches BDU's
  `vulxml.zip` and NVD's yearly `nvdcve-2.0-<year>.json.gz` files and
  points `cve.bdu.path` / `cve.nvd.path` in `enodia.yaml` at them (a file,
  or for NVD a directory of files). Either source works alone. Both are
  stream-parsed and cached in the OS cache directory: the first run after
  a database changes takes about a minute for all of NVD plus BDU, every
  later run under a second.
- **53 products matched**, every probe with usable data in either source,
  each vendor/product pair verified verbatim against the full real exports
  (D33). Deliberately not matched, each for a stated reason:
  general-purpose Linux distributions (their CVEs are package-level), the
  BSDs and Solaris, ESXi/vCenter and Synology DSM (patch levels and build
  suffixes the matcher doesn't read yet).
- **Edition-aware matching** for GitLab, Vault, Nextcloud and MongoDB: a
  Community Edition instance no longer sees Enterprise-only findings (on
  real data, GitLab 19.2.2 CE sees 4 of NVD's 9, Nextcloud 27.1.3 CE 11 of
  23). The `gitlab`, `vault`, `nextcloud` and `mongodb` probes report
  their server's own edition in `Extra["enterprise"]`; an unknown edition
  keeps every finding (D33, D34).
- `ssh` targets are matched as OpenSSH or Dropbear by their banner, and
  any other SSH stack gets no CVE lookup rather than OpenSSH's (D33).
- A **CVES column** in `check`'s compact and drift views, counting
  distinct CVEs.
- A **per-CVE modal** in `export --format html`, pure CSS with no
  JavaScript, so the inline report stays a zero-`<script>` offline file
  (D32): one line per CVE with links to NVD, cve.org and bdu.fstec.ru,
  BDU's Russian text when BDU has the CVE, a colored
  `CRITICAL · CVSS 3.1 9.8` rating, most severe first (D35).
- `export --format json` carries every per-source finding under each
  assessment's `cves`, including a structured CVSS rating parsed from both
  sources.
- `fortios` probe for Fortinet FortiGate, via its REST API with a REST API
  Admin token (D29).
- CDN-mode HTML reports remember a dismissed "needs internet access"
  warning per viewer.

### Notes

- The `cve:` block is read from whichever config the run actually uses —
  `--config`, `$ENODIA_CONFIG`, or the default search paths.
- Windows paths work unquoted, in single quotes, with forward slashes or
  as UNC paths. In YAML double quotes `\t` and `\n` become a tab and a
  newline, so such a path is rejected at load with a hint.
- `cisco-ios-xe` is off the roadmap for good (D34).

## [1.2.1+0] — 2026-09-10

### Fixed

- `p4d`/`p4p` didn't apply `t.Timeout` to the `p4` CLI subprocess they shell
  out to — every other probe in this tree clamps its network transport to
  `t.Timeout` before touching the network, and this one didn't. A `p4`
  process stuck dialing an unreachable direct server (no response, no RST —
  the exact network behavior D28 already documents) hung indefinitely,
  stalling an entire collection run. Reported directly from a real hang in
  production.

## [1.2.0+0] — 2026-09-10

### Added

- `p4d` and `p4p` probes for Perforce Helix Core Server and Perforce Proxy.
  Perforce's own RPC wire protocol was fully reverse-engineered live and a
  hand-built client reproduced its handshake correctly against a real proxy,
  but that exact, byte-verified-correct handshake is silently dropped by
  real direct p4d servers for reasons not visible from the client side
  (mandatory TLS and rate limiting both ruled out live). Both probes shell
  out to the operator's own `p4` CLI instead (`p4 -Ztag -p <address> info`)
  — the first probe in this project to run an external process rather than
  speak a wire protocol directly. The binary path is configurable per
  target via `options.binary` (falling back to `p4` on `$PATH`); this
  works identically on Windows, pointed at `p4.exe`. A proxy's reply is
  told apart from a direct server's by the presence of its own
  `proxyVersion` field — each probe rejects the other's shape (D28).

### Fixed

- The `p4 -Ztag` output parser didn't strip Windows line endings: a real
  `p4.exe` writes `\r\n`, leaving a trailing `\r` inside field values like
  `ServerID`.
- `probe.Observation.Resolver` (added in 1.1.0+0 for sonarqube) was a plain
  `ResolverRef`, not a pointer — `encoding/json`'s `omitempty` has no
  concept of "empty" for a struct value, so every single observation was
  serialising a spurious `"resolver":{}`, not just sonarqube's. Changed to
  `*ResolverRef`, the same reason `TLSVerified` is already `*bool`.

## [1.1.1+0] — 2026-09-10

### Fixed

- `debian` was reporting a bare major version (`13`) instead of the actual
  point release (`13.6`) — confirmed live that Debian's `/etc/os-release`
  `VERSION_ID` never carries one, even on a fully patched install; the point
  release lives only in `/etc/debian_version`. `debian` moved off the shared
  `osReleaseFamilyProbe` into its own `debianProbe`, which reads both files
  and only trusts `debian_version` after confirming `ID=debian` and that its
  content is a plain dotted number — a real Ubuntu image was confirmed live
  to ship the identical file with meaningless inherited content (D26).
- `ubuntu` had the same gap: `VERSION_ID` never changes after a release
  ships (confirmed live, `14.04` through `24.10`), so a fully patched `22.04`
  host reported bare `22.04`, not `22.04.5`. `ubuntu` moved off
  `osReleaseFamilyProbe` into its own `ubuntuProbe`, preferring the point
  release from `os-release`'s own `VERSION` field when it's strictly more
  precise than `VERSION_ID`. Every other `osReleaseFamilyProbe` product was
  audited the same way; none of the rest have this gap (D27).

## [1.1.0+0] — 2026-09-10

### Added

- `resolver.githubTagsSource` (`Type: "github-tags"`): a lifecycle source for
  products that publish no GitHub Releases at all, only tags in a non-dotted
  shape. Used to give `pgadmin` its first working resolver
  (`pgadmin-org/pgadmin4`'s tags are `REL-9_17`, converted to `9.17`; the
  highest-parsing tag is picked, not the first one, since the tags endpoint
  documents no ordering guarantee) (D24).
- `GITHUB_TOKEN` environment variable: authenticates every GitHub lifecycle
  lookup (both `github` and `github-tags`), raising GitHub's unauthenticated
  cap from 60 requests/hour per source IP to 5000/hour (D24).
- `probe.Observation.Resolver`: lets a probe pick which lifecycle calendar
  applies per observation, overriding its product's static
  `Meta().DefaultResolver`, for the rare case where the right calendar can
  only be told apart *after* seeing the vendor's own version reply. First
  used to split `sonarqube` between SonarQube Server and SonarQube Community
  Build — two separate products since SonarSource's late-2024 split, tracked
  as two different `endoflife.date` pages with different cycle data (D25).

### Fixed

- Resolver failures used to show only `resolver_error` in the report, with no
  way to tell a GitHub rate limit from a DNS failure from a reshaped API.
  `enodia check`/`export` now print the real underlying error to stderr when
  this happens (D24).
- `sonarqube` was always compared against the `sonarqube-community` lifecycle
  calendar, even for a SonarQube Server instance — collecting its version
  worked, but the report showed an unmatched cycle regardless. Now resolved
  per instance from the version string itself (D25).

### Changed

- Container image publishing (`ghcr.io/epicmorg/enodia`, also mirrored to
  Docker Hub and Quay) moved out of this repository's own release pipeline
  entirely, into the `EpicMorg/docker` monorepo
  (`linux/ecosystem/apps/enodia`), on that repo's own build schedule. The
  published image address and tags (`latest`, `1`, the exact version) are
  unchanged; `.goreleaser.yaml` and `release.yml` no longer build or publish
  any container at all (D17).

## [1.0.0+0] — 2026-09-09

Initial release. `collect → inventory.jsonl → evaluate → assessment → render`,
end to end, verified against real production infrastructure:

- **87 probes**, one file each, compiled in and explicitly registered — most
  speaking HTTP, some (Redis, PostgreSQL, MySQL, MongoDB) their own wire
  protocol directly, and a growing set (every mainstream Linux distro, the
  BSDs, macOS, OPNsense, Proxmox VE, TrueNAS, Synology DSM, network
  appliances) reached over SSH or a vendor HTTP API instead of assuming a
  version endpoint exists at all.
- `product: generic` — a config-only probe (`json`/`xml`/`header`/
  `plaintext`/`regex` plus `clean_regex`) for anything in-house, with a
  deliberately frozen vocabulary (no conditionals, loops, or templating).
- Lifecycle resolution against **endoflife.date** and **GitHub Releases**,
  cached on disk, evaluated on three independent axes (patch drift,
  lifecycle phase, newer branch) rather than one collapsed verdict.
- Four report views (`compact`, `lifecycle`, `drift`, `fleet`) across table,
  HTML (offline-first, optional CDN mode), JSON, and Prometheus output.
- `enodia serve` — a snapshot-only HTTP server; a background ticker collects,
  handlers only ever read the last snapshot.
- Config schema with `${VAR}`/`${VAR:-default}` interpolation, a dedicated
  credential store (`token-header`, `bearer`, `basic`, `ssh-key`, `password`),
  and TLS pinning/insecure-opt-in per target.
- Packaging: `.deb`, `.rpm`, `.apk`, and Arch's `.pkg.tar.zst`, a dedicated
  unprivileged `enodia` system user, man pages for every command, raw
  archives for Linux/Windows/macOS/Android (Termux), and a container image.
  Checksums signed with cosign keyless (OIDC, no key to manage or leak).
