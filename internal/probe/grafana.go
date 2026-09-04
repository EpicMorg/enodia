// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// grafanaProbe reads /api/health for the version.
//
// Confirmed live against a grafana/grafana container: this endpoint is
// intentionally public — it answered 200 with a valid body even with wrong
// Basic auth credentials, since it exists for a load balancer's liveness
// check, not as a normal protected API route. There is no credentialed
// path here to test or offer, so Auth carries no Kinds.
type grafanaProbe struct{}

func (grafanaProbe) Meta() Meta {
	return Meta{
		Product:         "grafana",
		Summary:         "Grafana",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "grafana"},
	}
}

// grafanaHealth is /api/health's full shape. Verified against a live
// server's real JSON reply (see testdata/grafana_13.2.1.json).
type grafanaHealth struct {
	Version  string `json:"version"`
	Commit   string `json:"commit"`
	Database string `json:"database"`
}

func (grafanaProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/health",
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

	var info grafanaHealth
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/health is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/health response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.Commit != "" {
		obs.Extra["commit"] = info.Commit
	}
	if info.Database != "" {
		obs.Extra["database"] = info.Database
	}
	return obs, nil
}
