// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// perforceSwarmProbe reads /api/version for the version.
//
// Confirmed live against several real production instances: the endpoint
// needs no credentials, and — usefully — the unversioned "/api/version"
// path (rather than a specific "/api/v11/version") returns the exact same
// body. Perforce has moved the API's floor version over the years (Swarm
// 2017.3's docs show only v7; 2018.2's show v9; the live instances checked
// here report supporting 9/10/11), so hardcoding any one vN risks a 401 —
// confirmed live too: an out-of-range version number (v99) answers 401,
// not 404, on an otherwise fully anonymous endpoint. The unversioned form
// sidesteps guessing which vN a given install still speaks.
type perforceSwarmProbe struct{}

func (perforceSwarmProbe) Meta() Meta {
	return Meta{
		Product:       "perforce-swarm",
		Summary:       "Perforce Helix Swarm",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no calendar under
		// "perforce-swarm", "helix-swarm", "swarm" or "perforce" (all
		// confirmed 404).
	}
}

// swarmVersionPattern splits "SWARM/2024.6/2710109 (2025/01/28)" into the
// version, changelist and release date. Verified against a live server's
// real JSON reply (see testdata/perforce_swarm_2024.6.json).
var swarmVersionPattern = regexp.MustCompile(`^SWARM/([0-9.]+)/(\d+)\s*\(([^)]*)\)$`)

// swarmVersionInfo is /api/version's full shape.
type swarmVersionInfo struct {
	APIVersions []int  `json:"apiVersions"`
	Version     string `json:"version"`
	Year        string `json:"year"`
}

func (perforceSwarmProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/version",
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

	var info swarmVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/version is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/version response carries no version", ErrUnparseable)
	}

	obs.Extra = map[string]string{"raw": info.Version}
	if m := swarmVersionPattern.FindStringSubmatch(info.Version); m != nil {
		obs.Version = m[1]
		obs.Extra["changelist"] = m[2]
		obs.Extra["releaseDate"] = m[3]
	} else {
		// Unrecognized format — keep the raw string rather than fail: it is
		// still the fact the server reported, just not the shape expected.
		obs.Version = info.Version
	}
	return obs, nil
}
