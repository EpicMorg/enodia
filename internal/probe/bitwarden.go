// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// bitwardenFamilyProbe reads /api/version for the version. Both Bitwarden
// (self-hosted) and Vaultwarden — a from-scratch Rust reimplementation of
// Bitwarden's server API, not a fork, with its own independent version
// numbering — expose the identical endpoint and response shape (a bare
// JSON string, not an object), confirmed live against real instances of
// each. They are registered as two distinct products below rather than
// merged into one: a probe pointed at a Vaultwarden install and labeled
// "bitwarden" would compare its version against the wrong lifecycle
// calendar the moment either gets one.
//
// The endpoint needs no credentials on either — client apps use it to
// check server compatibility before login exists.
type bitwardenFamilyProbe struct {
	product string
	summary string
}

func (p bitwardenFamilyProbe) Meta() Meta {
	return Meta{
		Product:       p.product,
		Summary:       p.summary,
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has neither a "bitwarden" nor
		// a "vaultwarden" calendar (both confirmed 404).
	}
}

func (p bitwardenFamilyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	var version string
	if err := json.Unmarshal(body, &version); err != nil {
		return obs, fmt.Errorf("%w: /api/version is not a valid JSON string: %w", ErrUnparseable, err)
	}
	if version == "" {
		return obs, fmt.Errorf("%w: /api/version was empty", ErrUnparseable)
	}

	obs.Version = version
	return obs, nil
}
