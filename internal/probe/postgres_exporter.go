// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// postgresExporterProbe reads the `postgres_exporter_build_info` gauge off
// /metrics — the prometheus/common "version collector" every Prometheus
// exporter in this ecosystem exposes the same way (a constant 1, version in
// a label, not the value). There is no other version source: this is a
// metrics endpoint, not a product with a REST API of its own.
//
// Confirmed live against a real prometheuscommunity/postgres-exporter
// container: /metrics needs no credentials by default and answers even when
// the target Postgres itself is unreachable (build_info describes the
// exporter binary, not the database it scrapes) — unrelated to postgres.go,
// which probes the database directly.
//
// exporter-toolkit (the library behind --web.config.file) can add HTTP
// Basic to this endpoint; AuthBasic is offered for that.
type postgresExporterProbe struct{}

func (postgresExporterProbe) Meta() Meta {
	return Meta{
		Product:       "postgres_exporter",
		Aliases:       []string{"postgres-exporter"},
		Summary:       "prometheus-community/postgres_exporter",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		// GitHub Releases, not endoflife.date: this is a Prometheus exporter,
		// not a product with a lifecycle/EOL policy of its own — there is a
		// "latest version" to compare against, never an eol/support date.
		DefaultResolver: ResolverRef{Type: "github", ID: "prometheus-community/postgres_exporter"},
	}
}

// postgresExporterBuildInfoPattern pulls the version label out of
// `postgres_exporter_build_info{branch="...",...,version="0.20.1",...} 1`
// regardless of label order — [^}]* stops at the line's own closing brace,
// so it can't run into a later, unrelated metric. Verified against a live
// server's real /metrics reply (see testdata/postgres_exporter_0.20.1.txt).
var postgresExporterBuildInfoPattern = regexp.MustCompile(`postgres_exporter_build_info\{[^}]*\bversion="([^"]+)"`)

func (postgresExporterProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/metrics",
		Accept: "text/plain",
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	body, err := ReadBody(resp)
	if err != nil {
		return obs, err
	}

	m := postgresExporterBuildInfoPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: /metrics has no postgres_exporter_build_info series", ErrNotSupported)
	}

	obs.Version = string(m[1])
	return obs, nil
}
