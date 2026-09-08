// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// logstashProbe reads "/" on Logstash's own HTTP monitoring API (port 9600
// by default, not the Elasticsearch or Kibana ports) — a node-info
// document with no authentication of its own; Logstash's monitoring API
// has no built-in auth at all and is meant to be firewalled off rather
// than credential-protected.
//
// Confirmed live against a real docker.elastic.co/logstash/logstash
// container.
type logstashProbe struct{}

func (logstashProbe) Meta() Meta {
	return Meta{
		Product:         "logstash",
		Summary:         "Logstash",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "logstash"},
	}
}

// logstashRootInfo is the subset of "/"'s reply this probe reads. Verified
// against a live server's real JSON reply (see
// testdata/logstash_8.15.0.json).
type logstashRootInfo struct {
	Version string `json:"version"`
}

func (logstashProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/",
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

	var info logstashRootInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: / is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: / response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	return obs, nil
}
