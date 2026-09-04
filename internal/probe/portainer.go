// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// portainerProbe reads /api/system/status for the version.
//
// Confirmed live against a portainer/portainer-ce container: this endpoint
// (and its older alias, /api/status, which answers identically) is
// intentionally public — reachable before the mandatory first-run admin
// account has even been created, since a UI needs to show something before
// login exists. There is no credentialed path here to test or offer, so
// Auth carries no Kinds.
type portainerProbe struct{}

func (portainerProbe) Meta() Meta {
	return Meta{
		Product:       "portainer",
		Summary:       "Portainer",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no portainer calendar
		// (confirmed: GET .../api/portainer.json is a 404).
	}
}

// portainerStatus is /api/system/status's full shape. Verified against a
// live server's real JSON reply (see testdata/portainer_2.45.0.json).
type portainerStatus struct {
	Version    string `json:"Version"`
	InstanceID string `json:"InstanceID"`
}

func (portainerProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	var info portainerStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/system/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/system/status response carries no Version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.InstanceID != "" {
		obs.Extra["instanceId"] = info.InstanceID
	}
	return obs, nil
}
