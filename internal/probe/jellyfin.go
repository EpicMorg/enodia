// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// jellyfinProbe reads /System/Info/Public for the version.
//
// Confirmed live against a real production instance: this "Public" variant
// of the system-info endpoint is intentionally reachable without
// credentials — a client app needs it before login exists — but the same
// response also carries this specific deployment's own ServerName, a
// persistent install Id, and its LocalAddress. None of that describes the
// software itself, so only Version and ProductName (used for the identity
// check below) are read here.
type jellyfinProbe struct{}

func (jellyfinProbe) Meta() Meta {
	return Meta{
		Product:       "jellyfin",
		Summary:       "Jellyfin",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no jellyfin calendar
		// (confirmed: GET .../api/jellyfin.json is a 404).
	}
}

// jellyfinPublicInfo is the subset of /System/Info/Public this probe reads.
// Verified against a live server's real JSON reply (see
// testdata/jellyfin_10.11.11.json) — deliberately not the full shape; see
// the instance-identity note on jellyfinProbe.
type jellyfinPublicInfo struct {
	Version     string `json:"Version"`
	ProductName string `json:"ProductName"`
}

func (jellyfinProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/System/Info/Public",
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

	var info jellyfinPublicInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /System/Info/Public is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /System/Info/Public response carries no Version", ErrUnparseable)
	}

	// Vendor identity check, the same reasoning as the atlassian/zou probes.
	if info.ProductName != "" && info.ProductName != "Jellyfin Server" {
		return obs, fmt.Errorf("%w: this host reports ProductName=%q, expected \"Jellyfin Server\"",
			ErrNotSupported, info.ProductName)
	}

	obs.Version = info.Version
	return obs, nil
}
