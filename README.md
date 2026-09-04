
<div align="center">

![Enodia Logo](.github/img/512x256.png?raw=true "Enodia Logo")

**Know what you are running, and how long it has left.**

 [![Activity](https://img.shields.io/github/commit-activity/m/EpicMorg/enodia?label=commits&style=flat-square)](https://github.com/EpicMorg/enodia/commits) [![GitHub issues](https://img.shields.io/github/issues/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/issues) [![GitHub forks](https://img.shields.io/github/forks/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/network) [![GitHub stars](https://img.shields.io/github/stars/EpicMorg/enodia.svg?style=popout-square)](https://github.com/EpicMorg/enodia/stargazers)  [![Size](https://img.shields.io/github/repo-size/EpicMorg/enodia?label=size&style=flat-square)](https://github.com/EpicMorg/enodia/archive/master.zip) [![Release](https://img.shields.io/github/v/release/EpicMorg/enodia?style=flat-square)](https://github.com/EpicMorg/enodia/releases) [![License: AGPL v3](https://img.shields.io/github/license/EpicMorg/enodia?style=flat-square&color=fedcba
)](LICENSE)

</div>

> **Status: pre-alpha.** Architecture is settled, implementation is starting.
> Nothing here is stable yet.

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

**Time is a parameter.** Every evaluation takes an `asOf` date, so
`--as-of 2027-01-01` answers "what dies before next budget year" — and tests
stay deterministic instead of rotting.

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
