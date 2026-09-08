## What it does

```
          ░░
         ▒██▒
        ▓████▓
  ▓    ▓██████▓    ▓
 ▓█▓░  ▒██████▒  ░▓█▓
 ██████▓▒▓██▓▒▓██████
 ▒███████▓▒▒▓███████▒
  ░▒▓█████░░█████▓▒░
        ▒████▒
          ██
          ▒▒

█▀▀ █▄ █ █▀█ █▀▄ █ ▄▀█
██▄ █ ▀█ █▄█ █▄▀ █ █▀█ asks your deployed services what version they are running, then checks

those versions against vendor lifecycle calendars and tells you what is
already dead, what is dying, and where your fleet has drifted apart.

You describe your services once. Enodia handles the rest.
```

<div align="center">

**Know what you are running, and how long it has left.**

 [![Activity](https://img.shields.io/github/commit-activity/m/EpicMorg/enodia?label=commits&style=flat-square)](https://github.com/EpicMorg/enodia/commits) [![GitHub issues](https://img.shields.io/github/issues/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/issues) [![GitHub forks](https://img.shields.io/github/forks/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/network) [![GitHub stars](https://img.shields.io/github/stars/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/stargazers)  [![Size](https://img.shields.io/github/repo-size/EpicMorg/enodia?label=size&style=flat-square)](https://github.com/EpicMorg/enodia/archive/master.zip) [![Release](https://img.shields.io/github/v/release/EpicMorg/enodia?style=flat-square)](https://github.com/EpicMorg/enodia/releases) [![License: AGPL v3](https://img.shields.io/github/license/EpicMorg/enodia?style=flat-square&color=fedcba
)](LICENSE)

</div>

> **[docs.enodia.sh](https://docs.enodia.sh)** · full docs, config reference,
> and per-product probe notes.

> **Status: 1.0.** The full pipeline (collect → inventory → evaluate →
> render), 76 probes, `settings.yaml`, and the release/packaging pipeline are
> all implemented and used against real production infrastructure. See the
> [latest release](https://github.com/EpicMorg/enodia/releases/latest) for
> downloads.

---

## Example:

```yaml
schemaVersion: 1
targets:
  - id: jira-main
    product: jira
    address: https://jira.example.com

  - id: gitlab-main
    product: gitlab
    address: https://gitlab.example.com
    credentials: gitlab-token

credentials:
  gitlab-token:
    kind: token-header
    header: PRIVATE-TOKEN
    value: "${GITLAB_TOKEN}"
```

```console
$ enodia check
ID           PRODUCT  PATCH   LIFECYCLE  BRANCH     SEVERITY  REASON
jira-main    jira     behind  active     newer_lts  warn      -
gitlab-main  gitlab   behind  eol        newer      fail      -
```

Save this as `enodia.yaml` next to the binary — see "File locations" below
for every name and directory enodia actually searches, and the exact order.

## Why not something else

| Tool | Tracks upstream releases | Knows what you deployed | Lifecycle dates |
|---|---|---|---|
| `eol` CLI | — | — | yes |
| nvchecker | yes | — | — |
| Renovate / Dependabot | yes (dependencies) | — | — |
| what's-up-docker | yes (containers only) | containers only | — |
| Uptime Kuma | — | up/down only | — |
| **Enodia** | yes | **yes** | **yes** |

The gap Enodia fills is the join: inventory of the live fleet, matched against
lifecycle data.

## Design

**Two phases, deliberately separable.** Collection talks to your services;
evaluation talks to the internet. They almost never have network access to the
same places.

```
collect  →  inventory.jsonl  →  evaluate  →  assessment  →  render
```

For air-gapped environments this is the whole point:

```console
# inside the closed network — no internet needed
enodia collect --config config.yaml -o inventory.jsonl

# anywhere else — no access to your services needed
enodia check --from inventory.jsonl
```

**Three orthogonal axes, not one verdict.** A branch can be perfectly healthy
while a newer major exists — Confluence 10 LTS is alive and supported even
though 11 shipped. Collapsing that into a single status throws away the
information you actually wanted.

| Axis | Values |
|---|---|
| Patch | `current` · `behind` · `ahead` · `unknown` |
| Lifecycle | `active` · `security` · `eol` · `unknown` |
| Newer branch | `latest` · `newer` · `newer_lts` · `unknown` |

**Facts and judgement are separate.** The inventory records what was observed.
Severity is computed on top, from policy you control. Export the facts and
apply your own rules if ours do not fit.

**Time is a parameter.** Evaluation never calls the system clock itself — it
always takes `asOf` explicitly, sourced from the inventory's own collection
timestamp (`inventory.jsonl`'s `collectedAt`). Re-running `check --from` an
old inventory evaluates it as of *when it was collected*, not today, so
results and tests both stay deterministic instead of silently drifting with
the calendar.

**Probes are compiled in.** One product, one file, one entry in an explicit
registry. Adding support means a new release, not a plugin ABI. For anything
in-house, `product: generic` takes a parser spec straight from your config.

## Views

`check` and `export` both render one of four focuses, picked with `--view`
(or `settings.yaml`'s `render.default_view` when the flag isn't passed —
see "Reporting" below). Each view is a different slice of the same
inventory + assessment data, not a different data source.

**`compact`** (the default) — one row per target: the three axes, overall
severity, and why, if anything needs attention. This is what plain
`enodia check` shows, as in the example above.

**`lifecycle`** — when each target's lifecycle actually ends:

```console
$ enodia check --from inventory.jsonl --view lifecycle
ID           PRODUCT  LIFECYCLE  EOL         SUPPORT-ENDS  DAYS-TO-EOL
jira-main    jira     active     2026-12-05  -             338
gitlab-main  gitlab   eol        2025-01-16  2024-11-21    -350
```

**`drift`** — installed version against the latest release in the same
cycle:

```console
$ enodia check --from inventory.jsonl --view drift
ID           PRODUCT  CURRENT  LATEST   CYCLE  PATCH
jira-main    jira     10.3.1   10.3.25  10.3   behind
gitlab-main  gitlab   17.5.0   17.5.5   17.5   behind
```

**`fleet`** — version spread and reachability across every instance of a
product, grouped instead of listed one row per target. The offline-only
view: it needs nothing but the inventory itself, no lifecycle resolver, no
internet access at all. Two failed instances of the same product with
different failure kinds (auth vs. unreachable) get their own rows, not a
shared `(unknown)` bucket:

```console
$ enodia check --from inventory.jsonl --view fleet
PRODUCT  VERSION    STATUS       COUNT  INSTANCES
gitlab   (unknown)  auth         1      gitlab-2
gitlab   18.2.1     ok           1      gitlab-1
jira     (unknown)  unreachable  1      jira-staging
jira     10.3.1     ok           1      jira-3
jira     10.3.2     ok           2      jira-1, jira-2
```

`export --format json`/`prometheus` ignore `--view` entirely — they always
carry every observation and assessment; views only shape the table and the
HTML report (see "Reporting").

## Installation

Each [release](https://github.com/EpicMorg/enodia/releases/latest) carries a
`.deb`, `.rpm`, `.apk` and Arch's `.pkg.tar.zst` (linux/amd64+arm64)
alongside the raw archives, plus a container image:

```console
sudo dpkg -i enodia_linux_amd64.deb                # Debian/Ubuntu
sudo rpm -i enodia_linux_amd64.rpm                 # Fedora/RHEL
apk add --allow-untrusted enodia_linux_amd64.apk   # Alpine
sudo pacman -U enodia_linux_amd64.pkg.tar.zst      # Arch

docker run --rm \
  -v /etc/enodia:/config:ro \
  ghcr.io/epicmorg/enodia:1 check --config /config/config.yaml
```

The same image is also published to `docker.io/epicmorg/enodia` and Quay
— same tags, same multi-arch manifest, pick whichever registry you already
pull from.

All four packages install the binary at `/usr/bin/enodia`, man pages for
every command under `/usr/share/man/man1/` (`man enodia`, `man
enodia-collect`, ...), and create a dedicated, unprivileged `enodia` system
user — nothing in this package needs root to run, so `enodia serve` under
systemd shouldn't get any more than it does. Three empty directories are
created and chowned to that user: `/etc/enodia` (`root:enodia`, `0750` —
readable by the service via group membership, not writable by it — for your
`enodia.yaml`/`settings.yaml`/`credentials.yaml`; the package never writes a
config into it, a missing one is meant to be a loud error), and
`/opt/enodia`/`/var/enodia` (`enodia:enodia`, `0750`) for whatever the
service writes at runtime.

Or, for the raw archive rather than a package:

```console
curl -sSL https://raw.githubusercontent.com/EpicMorg/enodia/master/install.sh | sh   # Linux/macOS
irm https://raw.githubusercontent.com/EpicMorg/enodia/master/install.ps1 | iex        # Windows
```

## Supported platforms

| OS | Arch | Minimum version |
|---|---|---|
| Linux | amd64, arm64 | Kernel 3.2 or later — Debian 8+, Ubuntu 14.04+, RHEL/CentOS 7+ all comfortably qualify |
| Windows | amd64, arm64, 386 | Windows 10 / Windows Server 2016 or later |
| macOS | amd64, arm64 | macOS 12 Monterey or later |
| Android (Termux) | arm64 only | Android 7+ ([Termux's own floor](https://github.com/termux/termux-app)) — a separate `enodia_android_arm64` build, not the Linux one (see `docs/DECISIONS.md` D20); `amd64`/`386`/`arm` aren't built yet (D20/ROADMAP). **Rooted devices** (Magisk/KernelSU) may need `su` to run it at all, due to an open upstream bug, [termux-exec#40](https://github.com/termux/termux-exec/issues/40) — not something fixable from this side, see D20 |

These are the Go 1.26 toolchain's own floor (confirmed against
[go.dev/wiki/MinimumRequirements](https://go.dev/wiki/MinimumRequirements)
directly, not assumed), not something enodia adds on top — building from
source with a newer Go raises the macOS floor further (1.27 requires macOS
13 Ventura), since that's a toolchain decision, not a project one.
`CGO_ENABLED=0` (see `.goreleaser.yaml`) means the binary is fully static
and never links libc at all: on Linux, only the kernel version matters, not
which distro or glibc version is underneath.

## Reporting

`enodia export --format html` writes a single self-contained file. Point nginx
at it and refresh it from cron or a systemd timer.

There is no built-in web server and no refresh button, by design: a button that
polls your entire fleet on every click is a self-inflicted denial of service.
Collection runs on a schedule; the page shows the latest snapshot and states
plainly when it was taken.

An optional `settings.yaml` holds personal display defaults: which format
`export` uses when `--format` isn't passed, which table view `check`/`export`
use when `--view` isn't passed, and how `export --format html` renders — see
"File locations" below for every name and directory it's searched in, and why
a missing one is never an error the way a missing `enodia.yaml` is. For
example:

```yaml
schemaVersion: 1

export:
  # used whenever `export` is run without --format; the built-in default
  # stays json either way
  default_format: html

render:
  # compact (default) | lifecycle | drift | fleet
  default_view: fleet

html:
  # inline (default, fully offline) | cdn (loads Bootstrap/Bootswatch)
  assets: cdn

  # none (no stylesheet at all) | default (plain Bootstrap) | any of
  # Bootswatch's 26 real themes: brite, cerulean, cosmo, cyborg, darkly,
  # flatly, journal, litera, lumen, lux, materia, minty, morph, pulse,
  # quartz, sandstone, simplex, sketchy, slate, solar, spacelab,
  # superhero, united, vapor, yeti, zephyr
  theme: lumen

  # auto (default: races jsdelivr and cdnjs, uses whichever answers
  # first) | jsdelivr | cdnjs
  cdn: auto

  # optional: restrict the export to one view instead of all four
  # view: fleet
```

Every `html.*` field here only matters for `export --format html`; the
default `enodia check` table is unaffected by any of them except
`render.default_view`. See `docs/DECISIONS.md` D19 for the full reasoning,
including why a corrupted or unrecognised theme saved in a viewer's browser
resets to *this* file's `html.theme`, not to some hardcoded name.

### Row colors in CDN mode

With `html.assets: cdn`, `export --format html` gives each row a Bootstrap
contextual class — red for a failed instance, green for a reachable one (see
"Views" above for the plain data), in whatever Bootswatch theme is
configured, not a hardcoded color enodia has to maintain per theme. Here's
the fleet view's rows from the same data:

```html
<table class="table table-striped table-hover table-sm align-middle">
<thead><tr><th>PRODUCT</th><th>VERSION</th><th>STATUS</th><th>COUNT</th><th>INSTANCES</th></tr></thead>
<tbody>
<tr class="table-danger"><td>gitlab</td><td>(unknown)</td><td>auth</td><td>1</td><td>gitlab-2</td></tr>
<tr class="table-success"><td>gitlab</td><td>18.2.1</td><td>ok</td><td>1</td><td>gitlab-1</td></tr>
<tr class="table-danger"><td>jira</td><td>(unknown)</td><td>unreachable</td><td>1</td><td>jira-staging</td></tr>
<tr class="table-success"><td>jira</td><td>10.3.1</td><td>ok</td><td>1</td><td>jira-3</td></tr>
<tr class="table-success"><td>jira</td><td>10.3.2</td><td>ok</td><td>2</td><td>jira-1, jira-2</td></tr>
</tbody>
</table>
```

## File locations

Both files are found the same way: an explicit path always wins and must
exist (a typo must be an error, never a silent fall-through to some other
file), then a search — first match wins outright, nothing is merged from
several found files. Location beats naming: a match in the current directory
always wins over one in `$XDG_CONFIG_HOME`, which always wins over one in
`/etc/enodia/`, regardless of which name matched where.

**`enodia.yaml`** (`--config <path>` or `$ENODIA_CONFIG` for an exact file):

1. `./enodia.yaml`
2. `./enodia.yml`
3. `./config.yaml`
4. `./config.yml`
5. `./.enodia.yaml`
6. `./.enodia.yml`
7. `./.config.yaml`
8. `./.config.yml`
9. `$XDG_CONFIG_HOME/enodia/enodia.yaml` (`~/.config/enodia/enodia.yaml` if
   `$XDG_CONFIG_HOME` is unset)
10. `$XDG_CONFIG_HOME/enodia/enodia.yml`
11. `$XDG_CONFIG_HOME/enodia/config.yaml`
12. `$XDG_CONFIG_HOME/enodia/config.yml`
13. `/etc/enodia/enodia.yaml`
14. `/etc/enodia/enodia.yml`
15. `/etc/enodia/config.yaml`
16. `/etc/enodia/config.yml`

Finding nothing at all is an error: a config that can't be found is worth
failing loudly over, since it usually means the wrong file (or none) is
about to be used.

**`settings.yaml`** (`--settings <path>` or `$ENODIA_SETTINGS` for an exact
file) — same idea, with three differences: it also checks a plain `settings.`
name (not just `enodia.settings.`), it also checks the directory containing
the running executable (not just cwd — the actual "next to the binary" case,
which matters most on Windows: `install.ps1` puts `enodia.exe` in
`%LOCALAPPDATA%\enodia` and adds that to PATH, so cwd is rarely the install
directory), and finding nothing at all is *not* an error — every field just
falls back to its built-in default, since this file is entirely optional.
`enodia.yaml` does not get this executable-directory step: it carries
credentials, so it stays out of shared/portable install directories on
purpose.

1. `./enodia.settings.yaml`
2. `./enodia.settings.yml`
3. `./settings.yaml`
4. `./settings.yml`
5. `./.enodia.settings.yaml`
6. `./.enodia.settings.yml`
7. `./.settings.yaml`
8. `./.settings.yml`
9. `<directory of the running executable>/settings.yaml`
10. `<same>/settings.yml`
11. `$XDG_CONFIG_HOME/enodia/settings.yaml` (`~/.config/enodia/settings.yaml`
    if `$XDG_CONFIG_HOME` is unset)
12. `$XDG_CONFIG_HOME/enodia/settings.yml`
13. `/etc/enodia/settings.yaml`
14. `/etc/enodia/settings.yml`

## Third-party assets

`html.assets: cdn` loads Bootstrap and, unless `html.theme: none`, a
Bootswatch theme of it — both MIT licensed — from jsdelivr or cdnjs at the
moment someone opens the report in a browser. Neither is bundled into this
repository or into any release artifact; every CDN-mode report credits both
by name with a link to their license in its own footer. The default
`html.assets: inline` mode loads nothing external at all — see "Reporting"
above.

## Security

Enodia holds credentials to your infrastructure. Consequences, all deliberate:

- Credentials never appear in the inventory, in exported reports, or in logs.
- HTTPS is tried before HTTP. Credentials are never sent over plain HTTP unless
  you explicitly opt in per service.
- TLS verification is on by default. Custom CA and certificate pinning are
  supported so that `insecure: true` stays a last resort — and services checked
  without verification are flagged in the report.
- Secrets live in a separate `credentials.yaml` or environment variables, so
  your service inventory can be committed to git and your secrets cannot.

Found a hole? See [SECURITY.md](SECURITY.md).

## Contributing

Adding a product is one file plus one line in the registry, and a recorded
vendor response in `testdata/` so it stays honest. See
[CONTRIBUTING.md](CONTRIBUTING.md).

Contributions require signing the [CLA](CLA.md) — the bot handles it on your
first pull request. This exists so the project can be offered under commercial
terms alongside the AGPL; you keep the copyright to your work.

## Licence

Enodia is licensed under **AGPL-3.0-or-later**. See [LICENSE](LICENSE).

If the AGPL does not fit your situation, a commercial licence is available —
contact \<developer@epicm.org\>.

## The name

Enodia, "she of the wayside", is an epithet of Hecate: torchbearer, keeper of
crossroads. Fitting for something that lights up what is decaying and stands
where you choose which way to upgrade.
