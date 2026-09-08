// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"strings"
	"time"
)

// testrailProbe reads /version.txt for the version.
//
// TestRail ships this as a plain static file in its web root — confirmed
// live against a real production instance — rather than a REST API
// response; its own documented REST API (get_current_user and friends)
// needs credentials and doesn't carry the product version at all. No
// credentials are needed here.
type testrailProbe struct{}

func (testrailProbe) Meta() Meta {
	return Meta{
		Product:       "testrail",
		Summary:       "TestRail",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no testrail calendar
		// (confirmed: GET .../api/testrail.json is a 404).
	}
}

func (testrailProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/version.txt",
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

	version := strings.TrimSpace(string(body))
	if version == "" {
		return obs, fmt.Errorf("%w: /version.txt was empty", ErrUnparseable)
	}

	obs.Version = version
	return obs, nil
}
