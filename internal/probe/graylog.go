// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// graylogProbe reads /api/ — the REST API's own root resource, a public
// discovery document every Graylog node answers with no credentials.
//
// Confirmed live against a real graylog/graylog container (plus the
// MongoDB and Elasticsearch it depends on): the root answers
// {"cluster_id":...,"node_id":...,"version":"4.3.15+17ed3ac","tagline":...}
// anonymously.
type graylogProbe struct{}

func (graylogProbe) Meta() Meta {
	return Meta{
		Product:         "graylog",
		Summary:         "Graylog",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "graylog"},
	}
}

// graylogRootInfo is the subset of /api/'s reply this probe reads.
// Verified against a live server's real JSON reply (see
// testdata/graylog_4.3.15.json).
type graylogRootInfo struct {
	Version string `json:"version"`
}

func (graylogProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/",
		Accept: "application/json",
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

	var info graylogRootInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/ is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/ response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	return obs, nil
}
