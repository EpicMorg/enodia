# Roadmap

Not dates. Order of work, and what each step unblocks.

## Done

- `internal/probe` — interface, HTTP helper, TLS settings, typed errors
- `internal/probe` — atlassian (jira/confluence/bitbucket/bamboo), generic
- `internal/version` — normalisation, comparison, cycle matching
- `internal/collect` — concurrent runner, retry policy, warnings
- `internal/inventory` — JSONL writer/reader, schema versioning
- Tests on recorded fixtures, offline, `-race` clean

## Next — config

`internal/config`. Blocks everything else.

- Schema with a `schemaVersion`, validated with clear errors
- `${VAR}` and `${VAR:-default}` interpolation
- Credential store: named credentials, separate `credentials_file`, env vars
- Resolution order: `--config`, `$ENODIA_CONFIG`, `./enodia.yaml`,
  `./.enodia.yaml`, `$XDG_CONFIG_HOME/enodia/`, `/etc/enodia/`
- First match wins; no layered merging
- An explicit `--config` path that does not exist is an error, never a fallback
- Warn when `credentials.yaml` is more permissive than 0600

## Then — resolver

`internal/resolver`. Turns an inventory into an assessment.

- endoflife.date, with an on-disk cache keyed by product and a TTL
- Cache matters: fifty services resolve to roughly eight distinct products
- GitHub Releases as a fallback for products with no lifecycle calendar
- A missing resolver is a normal state, not an error — inventory-only

## Then — evaluate

`internal/evaluate`. The product's actual value.

- Three axes per D6, computed against `asOf`
- Cycle matching with a per-product override hook for vendors whose branch
  naming does not fit the default
- Policy: `warn_days`, `fail_on`, per-axis severity
- Distinguish probe failure / lifecycle unknown / cycle unmatched. The third
  usually means something genuinely odd and must not be buried in "unknown"

## Then — CLI

`cmd/enodia`, cobra.

- `collect`, `check`, `export`, `config path|validate|resolve`, `products`,
  `version`, `completion`
- `SilenceUsage: true` — a runtime error must not dump the whole help into CI logs
- Exit codes: 0 ok, 1 internal error, 2 bad arguments, 3+ policy findings.
  "The tool crashed" and "the tool found a problem" must be distinguishable

## Then — render

- Table with selectable views: compact, lifecycle, drift, fleet
- The fleet view — version spread across instances of one product — is the
  offline-only feature and may be the most useful one in closed networks
- JSON, Prometheus textfile, single-file HTML

## Then — packaging

- goreleaser: binaries, checksums, signatures
- Container from scratch, non-root, CA bundle copied in — without it every
  TLS call fails with an unhelpful error
- Install script served from a path, never the site root, and never
  User-Agent-dependent
- GitHub Action wrapping the container

## Later

- More probes: teamcity, gitlab, jenkins, sonarqube, artifactory, vault,
  grafana, keycloak, nextcloud, elasticsearch, portainer
- Non-HTTP probes: redis, postgresql, mysql, ssh banner. These validate D10;
  MySQL is the interesting one — the version arrives before authentication
- `serve` mode, snapshot-only, behind a reverse proxy
- CVE correlation via OSV.dev — blocked, see DECISIONS.md D18: OSV's query
  API doesn't reliably cover any probe enodia has today (Atlassian has zero
  coverage, and the open-source ones report upstream versions that don't
  match OSV's distro-package version format)
- Historical tracking — a directory of dated inventories is already most of it

## Deliberately not planned

- Hosted SaaS
- A refresh button that triggers collection
- Any growth of the generic probe's vocabulary
- Built-in authentication for `serve`
