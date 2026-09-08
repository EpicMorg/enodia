// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// youtrackProbe reads /api/config?fields=version.
//
// Confirmed live against a real, internet-facing YouTrack instance: this
// endpoint needs no credentials, and asking for any field beyond "version"
// (buildDate, edition, ...) gets silently ignored rather than returned — an
// anonymous caller only gets the version back, so that is all this probe
// asks for.
type youtrackProbe struct{}

func (youtrackProbe) Meta() Meta {
	return Meta{
		Product:         "youtrack",
		Summary:         "YouTrack",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "youtrack"},
	}
}

// youtrackConfig is the anonymous subset of /api/config. Verified against a
// live server's real JSON reply (see testdata/youtrack_2026.3.json).
type youtrackConfig struct {
	Version string `json:"version"`
}

func (youtrackProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/config?fields=version",
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

	var cfg youtrackConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return obs, fmt.Errorf("%w: /api/config is not valid JSON: %w", ErrUnparseable, err)
	}
	if cfg.Version == "" {
		return obs, fmt.Errorf("%w: /api/config response carries no version", ErrUnparseable)
	}

	obs.Version = cfg.Version
	return obs, nil
}
