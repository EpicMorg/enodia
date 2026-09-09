// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/EpicMorg/enodia/internal/version"
)

// sonarqubeProbe reads /api/system/status for the version.
//
// Confirmed live against a sonarqube:lts-community container: this endpoint
// (along with /api/server/version and /api/system/ping) stays reachable
// without credentials even after enabling the "Force user authentication"
// global setting — SonarQube treats it as a health-check endpoint a load
// balancer needs to reach with no login, not a normal API route. So there
// is no credentialed path to test or offer here; Auth carries no Kinds.
//
// SonarSource split "SonarQube" into two products at the end of 2024:
// "SonarQube Server" (the direct continuation — every former Community/
// Developer/Enterprise/Data Center edition merged into one build, still
// calendar-versioned "2025.1", "2026.4", ...) and "SonarQube Community
// Build" (a new, separate, always-free build with its own faster cadence,
// versioned "24.12", "25.12", "26.9", ... — same calendar scheme, two-digit
// year instead of four). endoflife.date tracks these as two separate pages
// with genuinely different cycle data, confirmed live. Both pages carry
// identical history for versions from before the split (bare majors like
// "9.9.8.100196", "10.7.0.96327"), so which one those resolve against
// doesn't change the answer. sonarqubeResolverFor tells them apart from the
// version string alone — no extra request, no operator-declared variant
// needed, since the two schemes can't collide.
type sonarqubeProbe struct{}

func (sonarqubeProbe) Meta() Meta {
	return Meta{
		Product:       "sonarqube",
		Summary:       "SonarQube (Server or Community Build)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// The real resolver is chosen per observation (see
		// sonarqubeResolverFor) once the version is known; this is only
		// what `enodia products` shows before any target has been probed.
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "sonarqube-server"},
	}
}

// sonarqubeResolverFor picks the matching endoflife.date page for a
// SonarQube version string. A four-digit leading year ("2025.x", "2026.x")
// is SonarQube Server; a two-digit one from 2024 onward ("24.x"..) is
// Community Build; anything smaller is a pre-split bare major version,
// which is identical on both pages, so it defaults to sonarqube-community
// — the more direct lineage of the historic free "Community Edition" name.
func sonarqubeResolverFor(rawVersion string) ResolverRef {
	parts := version.Parts(rawVersion)
	if len(parts) > 0 {
		switch {
		case parts[0] >= 2000:
			return ResolverRef{Type: "endoflife", ID: "sonarqube-server"}
		case parts[0] >= 20:
			return ResolverRef{Type: "endoflife", ID: "sonarqube-community"}
		}
	}
	return ResolverRef{Type: "endoflife", ID: "sonarqube-community"}
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
	obs.Resolver = sonarqubeResolverFor(info.Version)
	obs.Extra = map[string]string{}
	if info.ID != "" {
		obs.Extra["id"] = info.ID
	}
	if info.Status != "" {
		obs.Extra["status"] = info.Status
	}
	return obs, nil
}
