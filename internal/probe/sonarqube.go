// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// sonarqubeProbe reads /api/system/status for the version.
//
// Confirmed live against a sonarqube:lts-community container: this endpoint
// (along with /api/server/version and /api/system/ping) stays reachable
// without credentials even after enabling the "Force user authentication"
// global setting — SonarQube treats it as a health-check endpoint a load
// balancer needs to reach with no login, not a normal API route. So there
// is no credentialed path to test or offer here; Auth carries no Kinds.
type sonarqubeProbe struct{}

func (sonarqubeProbe) Meta() Meta {
	return Meta{
		Product:         "sonarqube",
		Summary:         "SonarQube",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "sonarqube-community"},
	}
}

// sonarqubeStatus is /api/system/status's full shape. Verified against a
// live server's real JSON reply (see testdata/sonarqube_9.9.8.100196.json).
type sonarqubeStatus struct {
	ID      string `json:"id"`
	Version string `json:"version"`
	// Status is one of UP, DOWN, STARTING, RESTARTING, DB_MIGRATION_NEEDED,
	// DB_MIGRATION_RUNNING — a fact about server health, not a verdict this
	// probe gets to make (D7), so it is recorded as-is rather than turned
	// into an error when it isn't UP.
	Status string `json:"status"`
}

func (sonarqubeProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/system/status",
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

	var info sonarqubeStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/system/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/system/status response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.ID != "" {
		obs.Extra["id"] = info.ID
	}
	if info.Status != "" {
		obs.Extra["status"] = info.Status
	}
	return obs, nil
}
