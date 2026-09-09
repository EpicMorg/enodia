# Changelog

Notable changes to enodia, release by release. Tags follow this project's own
`MAJOR.MINOR.PATCH+BUILD` scheme, no `v` prefix (see `docs/DECISIONS.md` D17);
`+BUILD` is semver build metadata, used only for a rebuild with no functional
change, not to sidestep a real version bump. Full reasoning behind any change
below lives in `docs/DECISIONS.md`, referenced by its `D`-number.

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
