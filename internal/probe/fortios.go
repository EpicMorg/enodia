// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strconv"
	"time"
)

// fortiosProbe reads /api/v2/monitor/system/status for the version.
//
// Confirmed live against a real FortiGate 601E running FortiOS 7.4.12: a
// plain Authorization: Bearer <token> — a REST API Admin's own API key,
// generated once in the GUI and shown exactly once — is enough. No
// query-string access_token, no session/CSRF dance; the same shape
// AuthBearer already sends for every other bearer-token probe here, so no
// new AuthKind was needed. This is the documented HTTP API D23 expected
// to fit better than SSH CLI-scraping once real hardware access existed
// to confirm it live.
//
// Missing or wrong tokens both answer HTTP 401 with an Apache-style HTML
// error page, not JSON — confirmed live — but FetchHTTP already turns
// 401/403 into ErrAuth before this probe ever sees the body, so there is
// no HTML-shaped response to parse here.
type fortiosProbe struct{}

func (fortiosProbe) Meta() Meta {
	return Meta{
		Product:         "fortios",
		Summary:         "Fortinet FortiOS (FortiGate)",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "fortios"},
	}
}

// fortiosStatus is /api/v2/monitor/system/status's shape. Verified against
// a live device's real JSON reply (see testdata/fortios_v7.4.12.json).
type fortiosStatus struct {
	Version string `json:"version"`
	Build   int    `json:"build"`
	Results struct {
		Model    string `json:"model"`
		Hostname string `json:"hostname"`
	} `json:"results"`
}

func (fortiosProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v2/monitor/system/status",
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

	var info fortiosStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/v2/monitor/system/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/v2/monitor/system/status response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.Results.Model != "" {
		obs.Extra["model"] = info.Results.Model
	}
	if info.Build != 0 {
		obs.Extra["build"] = strconv.Itoa(info.Build)
	}
	return obs, nil
}
