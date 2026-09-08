// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// kibanaProbe reads /api/status — deliberately unauthenticated by design
// (it's what orchestrators use as a liveness/readiness probe; the official
// Elastic Helm chart's own readinessProbe curls this exact path with no
// credentials), so this needs none either.
//
// Confirmed live against a real docker.elastic.co/kibana/kibana container
// (backed by a real Elasticsearch): the reply carries the full version
// even while Kibana is still starting up and answering 503 for
// "not ready yet" — status code aside, the body already has it.
type kibanaProbe struct{}

func (kibanaProbe) Meta() Meta {
	return Meta{
		Product:         "kibana",
		Summary:         "Kibana",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "kibana"},
	}
}

// kibanaStatusInfo is the subset of /api/status this probe reads. Verified
// against a live server's real JSON reply (see
// testdata/kibana_8.15.0.json).
type kibanaStatusInfo struct {
	Version struct {
		Number string `json:"number"`
	} `json:"version"`
}

func (kibanaProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:       "/api/status",
		Accept:     "application/json",
		OKStatuses: []int{503}, // "not ready yet" during startup; the body still carries the version
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

	var info kibanaStatusInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version.Number == "" {
		return obs, fmt.Errorf("%w: /api/status response carries no version.number", ErrUnparseable)
	}

	obs.Version = info.Version.Number
	return obs, nil
}
