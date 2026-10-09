# Changelog

Notable changes to enodia, release by release. Tags follow this project's own
`MAJOR.MINOR.PATCH+BUILD` scheme, no `v` prefix (see `docs/DECISIONS.md` D17);
`+BUILD` is semver build metadata, used only for a rebuild with no functional
change, not to sidestep a real version bump. Full reasoning behind any change
below lives in `docs/DECISIONS.md`, referenced by its `D`-number.

## [Unreleased]

### Added

- `enodia cve update`: downloads the CVE databases every configured
  `cve.*.path` names — BDU, NVD (this year, last year and missing years;
  `--all-years`), Debian, OVAL and Alpine (the releases already on disk,
  those `--from` inventories need, `--oval`/`--alpine`), MariaDB,
  Atlassian, PostgreSQL (`--postgresql` for per-major pages) and nginx.
  If-Modified-Since; a download replaces a file only after it loads. TLS
  is verified against the system roots plus `cve.update.ca_file` and
  `cve.update.ca_dir`, or not at all with `cve.update.tls_skip_verify`.
  Every other command still never downloads anything (D73).
- `splunk` probe: splunkd's management API on 8089 with Basic or a Splunk
  token (D67).
- `code-server` probe: `codeServerVersion` from the login page (D66).
- `phpipam` probe: the login page's footer and asset version (D65).
- `domainmod` probe: the CHANGELOG in its web root (D65).
- `netdata` probe: the agent's anonymous `/api/v1/info` (D64).
- `libretranslate` probe: the public OpenAPI document `/spec` (D64).
- `torrserver` probe: `/echo` (D64).
- `kafka` probe: the broker's version over SSH from its own jar, optionally
  in a container; Confluent Platform builds are reported as `confluent`
  with the Apache Kafka line they carry (D63).
- `home-assistant` probe: `/api/config` with a long-lived access token,
  `kind: bearer` (D62).
- `openhab` probe: the anonymous REST root `/rest/` (D62).
- `doxygen` probe: which Doxygen generated a docs site, from its generator
  mark (D61).
- `qbittorrent` probe: the Web UI API after a form login, `kind: password`
  (D61).
- `netbox` probe: the anonymous login page's `data-netbox-version` (D60).
- `greenbone` probe (aliases `openvas`, `gsad`): gsad's version from the
  envelope of its `/gmp` reply, unauthenticated (D60).
- `posthog` probe: self-hosted PostHog's git commit from its anonymous
  login page (D59).
- `uptime-kuma` probe: logs in over Uptime Kuma's socket.io API with a
  username and password (`kind: password`) and reads the version it sends
  after login (D58).
- `wapt` probe: the WAPT server's anonymous `/ping` (D57).
- `minio` probe: `minio --version` over SSH, optionally in a container;
  MinIO's `RELEASE.<timestamp>` names now compare as versions (D56).
- `sentry` probe: self-hosted Sentry's version from its anonymous login
  page (D55).
- `zookeeper` probe: the `srvr` four-letter word (D54).
- `ghost` probe: the anonymous `/ghost/api/admin/site/`, which gives
  major.minor (D54).
- `onlyoffice` and `euro-office` probes: ONLYOFFICE Docs and its
  Euro-Office fork (as shipped for Nextcloud), read anonymously from the
  document server's `/index.html`; a server of the other brand is refused
  with the product to use (D53).
- `weblate` probe: the anonymous "Powered by Weblate" footer, GitHub
  resolver (D52).
- `memcached` probe: the text protocol's `version` command, no
  credentials (D51).
- `rabbitmq` probe: the management plugin's `/api/overview`, `kind: basic`
  (D51).
- `cassandra` probe: `release_version` over the CQL native protocol v4,
  `kind: password` when the cluster has PasswordAuthenticator (D51).
- CVEs for `mariadb` targets. BDU and NVD now cover MariaDB, and a new
  `cve.mariadb.path` reads MariaDB's own fixed-CVE table
  (`community-server.md`), which knows the fix release per series. Merged
  with BDU and NVD; where MariaDB's table knows a CVE, its verdict
  replaces their open-ended ranges, so the latest release of a maintained
  series is no longer flagged for CVEs fixed only in newer series (D50).
- CVEs for 24 more products: cassandra, code-server, domainmod, doxygen,
  ghost, greenbone, home-assistant, kafka, memcached, minio, netbox,
  netdata, onlyoffice, openhab, pfsense, phpipam, qbittorrent, rabbitmq,
  sentry, splunk, uptime-kuma, wapt, weblate, zookeeper. MinIO's
  timestamp versions compare; pfSense CE and Splunk Enterprise skip
  ranges for other editions; Confluent Kafka builds get no lookup (D68).
- CVEs for `hp-ilo4`, `dell-idrac` and `synology-dsm`. iDRAC is matched
  per generation, read from the Redfish model ("13G" is iDRAC8); with no
  model only iDRAC9's 3.x and later are looked up. DSM compares version,
  build and Update ("7.2.1-69057-6"); the probe now reports the Update
  in `Extra["update"]` (D72).
- `cve.atlassian.path`: Atlassian's own per-release CVE data
  (vuln-transparency API) for `jira`, `confluence`, `bitbucket` and
  `bamboo`, third-party dependency CVEs included. Judged within each
  branch, merged with BDU and NVD; for a release Atlassian lists, its
  verdict wins (D69).
- `cve.postgresql.path` and `cve.nginx.path`: the projects' own security
  pages (HTML, saved as is), with the fix release per branch. Merged with
  BDU and NVD; where they know a CVE, their verdict wins. Current
  PostgreSQL 17/16/15/14 releases and nginx 1.30.5 no longer show BDU's
  branchless ranges (D71).
- `PRIVACY.md`: what enodia connects to (your targets, endoflife.date,
  the GitHub API — product and repository names only) and what it stores
  (only your own files and a local cache). No telemetry.

### Changed

- The `github` resolver skips releases whose tag names a pre-release
  (`5.3.0.M2`, `2026.10.0b7`, `-rc1`, `-beta.1`) even when GitHub doesn't
  flag them (D62).
- The `github` resolver reads underscore-spelled (`Release_1_18_0`) and
  `release-`-prefixed (`release-5.2.4`) tags as versions (D61).
- The `github` resolver drops a leading `<repo>-`/`<repo>_` from release
  tags, so `weblate-2026.10` reads as `2026.10` in LATEST/CYCLE and in the
  comparison (D52).
- `teamcity` works without credentials: with none configured it reads the
  anonymous `/app/rest/server/version`, open on every TeamCity checked from
  2017.2 to 2026.1 even with guest login off. A token still selects
  `/app/rest/server` as before (D49).

### Fixed

- `jenkins` CVEs: a fixed LTS release is no longer flagged by the weekly
  range of the same fix (LTS 2.568.3 by "before 2.580"). Weekly and LTS
  ranges now apply only to their own release line (D70).
- The `github` resolver no longer fails on repositories whose releases
  list is over 1MiB (minio/minio's is 3.4MB): it now reads up to 8MiB
  (D56).
- A credential of a kind its product never sends is now a config error
  instead of being dropped silently. `kind: password` on an HTTP product
  (RouterOS, Harbor, ...) used to send the request with no `Authorization`
  header at all; `config validate` now names the kinds the product accepts
  — for a web login that is `kind: basic` (D48).

## [2.1.1+0] — 2026-10-08

### Fixed

- MariaDB 11.0+ no longer masks its version behind `5.5.5-` (`11.4.9-MariaDB-…`),
  so `mysql` recorded such servers as MySQL and `mariadb` refused them. Both
  probes now recognise MariaDB by either shape (D47).

## [2.1.0+0] — 2026-10-01

CVE correlation goes down to installed packages on twelve Linux
distributions, and six new probes land. Nothing breaks: the new `cve:`
keys are optional, and inventories only gain optional fields, so 2.0
configs and inventories work unchanged.

### Added

- **Package-level CVEs for Linux distributions** (D42–D44, D46). D33 left
  distributions out because a release number can't say which packages are
  patched; the OS probes now also read the installed packages and the
  running kernel in their one SSH round trip, and each distribution's own
  security data is matched per package. Each source is a file the operator
  downloads, like BDU and NVD:
  - `cve.debian.path` — the Debian Security Tracker's JSON, for `debian`.
  - `cve.oval.path` — vendor OVAL files, one per release, for `ubuntu`,
    `linuxmint` (via its Ubuntu base), `rhel`, `rocky-linux` (against
    Red Hat's file — Rocky's own is refused as unusable), `almalinux`,
    `oracle-linux`, `astra-linux` (SE 1.7/1.8) and `redos` (7.3/8.0).
    Parsed OVAL is cached like BDU and NVD.
  - `cve.alpine.path` — Alpine's secdb, for `alpine-linux`.
- Only CVEs that already have a fix newer than what's installed are
  reported — what an upgrade (and, for the kernel, a reboot) would close.
  One finding per package, linked to the advisory carrying the fix (USN,
  RHSA, ALSA, ELSA, Astra bulletin, ROS, Debian/Alpine tracker page), with
  every CVE folded under it in the HTML report.
- Matching follows each package manager's own rules: dpkg, rpm and apk
  version ordering (checked against apt_pkg, rpm and apk-tools on ~4000–
  5300 real version pairs each), AppStream module streams, Oracle's arch,
  FIPS and Ksplice variants, and the running kernel rather than whatever
  kernel packages are installed.
- Every source was cross-checked against the reference tool on real
  containers: `oscap oval eval` (Ubuntu 56/56 advisories, RHEL 128/128,
  AlmaLinux 197/197, Oracle 22/22, Astra 1.7 205/205 CVEs, Astra 1.8 48/48,
  RED OS 7.3 53/53, RED OS 8.0 60/60), `dnf updateinfo`, python3-apt and
  `apk version -t`.
- New probes: `mariadb` (D36), `pfsense` Community Edition over SSH (D37),
  `supermicro-bmc`, `dell-idrac` and `hp-ilo4` over Redfish (D40), and
  `freeradius` over SSH, with `options.container` for a FreeRADIUS in
  Docker or Podman (D45). 96 probes in total.
- `github-tag-branches` resolver: one lifecycle cycle per major.minor from
  GitHub tags, for projects maintaining several branches at once
  (FreeRADIUS 3.0.x and 3.2.x).
- FreeRADIUS mapped in both NVD and BDU.

### Fixed

- VMware's "8.0 U3k" shorthand now compares equal to "8.0.3" (D38).
- LATEST/CYCLE columns show cleaned versions for GitHub-resolved products,
  not the raw tag (`2026.9.1`, not `v2026.9.1`) (D39).
- `config validate` reports a missing `cve.*.path` file instead of passing
  and failing later in `check` (D41).

### Notes

- A Proxmox VE host gets package findings as a second, SSH `debian`
  target next to its API `proxmox` one; Debian's `linux` is only matched
  against a running Debian kernel, so Proxmox's own kernel isn't
  mistaken for one.
- With every source configured at once (BDU, NVD, Debian, eight OVAL
  files, Alpine) `check` took ~22s cold and ~3.4s warm, peaking at
  ~0.5–0.6GB — less if `cve.oval.path` holds only the releases you run.
- The repository's history was rewritten and re-signed to drop internal
  hostnames; every tag was re-created on the rewritten history. Release
  binaries up to 2.0.0+0 report commit hashes from before the rewrite.

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
