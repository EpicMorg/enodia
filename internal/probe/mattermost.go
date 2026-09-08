// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// mattermostProbe reads /api/v4/config/client?format=old for the version.
//
// Confirmed live against a real production instance: this endpoint is
// intentionally public — a login page needs it before any session exists —
// and needs no credentials.
//
// The real response is a full client-config dump (a hundred-plus keys):
// feature flags, SSO button colors, and genuinely identifying fields for
// that specific deployment (SiteName, SupportEmail, a telemetry/diagnostic
// ID, an asymmetric signing public key). None of those describe the
// software itself, so — the same reasoning as artifactory's license field —
// only Version and the handful of Build* fields that describe the build
// are read here; everything instance-identifying is left alone.
type mattermostProbe struct{}

func (mattermostProbe) Meta() Meta {
	return Meta{
		Product:         "mattermost",
		Summary:         "Mattermost",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "mattermost"},
	}
}

// mattermostClientConfig is the subset of the client config this probe
// reads. Verified against a live server's real JSON reply (see
// testdata/mattermost_11.7.2.json) — deliberately not the full shape; see
// the instance-identity note on mattermostProbe.
type mattermostClientConfig struct {
	Version     string `json:"Version"`
	BuildNumber string `json:"BuildNumber"`
	BuildHash   string `json:"BuildHash"`
}

func (mattermostProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v4/config/client?format=old",
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

	var cfg mattermostClientConfig
	if err := json.Unmarshal(body, &cfg); err != nil {
		return obs, fmt.Errorf("%w: config/client is not valid JSON: %w", ErrUnparseable, err)
	}
	if cfg.Version == "" {
		return obs, fmt.Errorf("%w: config/client response carries no Version", ErrUnparseable)
	}

	obs.Version = cfg.Version
	obs.Extra = map[string]string{}
	if cfg.BuildNumber != "" {
		obs.Extra["buildNumber"] = cfg.BuildNumber
	}
	if cfg.BuildHash != "" {
		obs.Extra["buildHash"] = cfg.BuildHash
	}
	return obs, nil
}
