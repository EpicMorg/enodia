
<div align="center">

![Enodia Logo](.github/img/512x256.png?raw=true "Enodia Logo")

**Know what you are running, and how long it has left.**

 [![Activity](https://img.shields.io/github/commit-activity/m/EpicMorg/enodia?label=commits&style=flat-square)](https://github.com/EpicMorg/enodia/commits) [![GitHub issues](https://img.shields.io/github/issues/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/issues) [![GitHub forks](https://img.shields.io/github/forks/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/network) [![GitHub stars](https://img.shields.io/github/stars/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/stargazers)  [![Size](https://img.shields.io/github/repo-size/EpicMorg/enodia?label=size&style=flat-square)](https://github.com/EpicMorg/enodia/archive/master.zip) [![Release](https://img.shields.io/github/v/release/EpicMorg/enodia?style=flat-square)](https://github.com/EpicMorg/enodia/releases) [![License: AGPL v3](https://img.shields.io/github/license/EpicMorg/enodia?style=flat-square&color=fedcba
)](LICENSE)

</div>

> **Status: pre-1.0.** The full pipeline (collect → inventory → evaluate →
> render), 29 probes, `settings.yaml`, and the release/packaging pipeline are
> all implemented and used against real production infrastructure — but no
> tagged release exists yet, and the config schema may still change before
> one does.

---

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

Save this as `enodia.yaml` (or `enodia.yml` — both work; `.yaml` wins if both
exist in the same place) in the current directory, `$XDG_CONFIG_HOME/enodia/`,
or `/etc/enodia/`. `--config <path>` or `$ENODIA_CONFIG` point at an exact
file instead, and a typo there is always an error, never a silent fall
through to some other config with different credentials.

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

## Installation

Not published yet. When it is:

```console
docker run --rm \
  -v /etc/enodia:/config:ro \
  ghcr.io/epicmorg/enodia:1 check --config /config/config.yaml
```

## Reporting

`enodia export --format html` writes a single self-contained file. Point nginx
at it and refresh it from cron or a systemd timer.

There is no built-in web server and no refresh button, by design: a button that
polls your entire fleet on every click is a self-inflicted denial of service.
Collection runs on a schedule; the page shows the latest snapshot and states
plainly when it was taken.

An optional settings file holds personal display defaults: which table view
`check`/`export` use when `--view` isn't passed, and how `export --format
html` renders. Same search locations as `enodia.yaml` above (current
directory, `$XDG_CONFIG_HOME/enodia/`, `/etc/enodia/`; `--settings <path>` or
`$ENODIA_SETTINGS` for an exact file), but a bare `settings.yaml`/`settings.yml`
next to the binary works too, not just the `enodia.`-prefixed form — and
unlike `enodia.yaml`, a missing settings file is never an error, every field
just falls back to its built-in default. For example:

```yaml
schemaVersion: 1

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

### The fleet view

`--view fleet` (or the `settings.yaml` above, which sets it as the default)
groups observations by product, installed version, and reachability instead
of one row per target — the offline-only view: it needs nothing but the
inventory itself, no lifecycle resolver, no internet access at all. Two
failed instances of the same product with different failure kinds (auth vs.
unreachable) get their own rows, not a shared "(unknown)" bucket:

```console
$ enodia check --view fleet --from inventory.jsonl
PRODUCT  VERSION    STATUS       COUNT  INSTANCES
gitlab   (unknown)  auth         1      gitlab-2
gitlab   18.2.1     ok           1      gitlab-1
jira     (unknown)  unreachable  1      jira-staging
jira     10.3.1     ok           1      jira-3
jira     10.3.2     ok           2      jira-1, jira-2
```

`export --format html` with `html.assets: cdn` renders the same rows with a
Bootstrap contextual class per row — red for a failed instance, green for a
reachable one, in whatever Bootswatch theme is configured, not a hardcoded
color enodia has to maintain per theme:

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
