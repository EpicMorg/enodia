// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// netdataProbe reads the agent's GET /api/v1/info, served without a login
// by default: {"version": "v2.12.1", "release-channel": "stable", ...}
// (confirmed live on netdata/netdata:stable). The same reply describes the
// host — uid, kernel, labels, hardware — so only version, release channel,
// architecture and container are read, and the fixture keeps only those.
type netdataProbe struct{}

func (netdataProbe) Meta() Meta {
	return Meta{
		Product:       "netdata",
		Summary:       "Netdata agent",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic, AuthBearer}},
		// No endoflife.date page.
		DefaultResolver: ResolverRef{Type: "github", ID: "netdata/netdata"},
	}
}

type netdataInfo struct {
	Version        string `json:"version"`
	ReleaseChannel string `json:"release-channel"`
}

func (netdataProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/api/v1/info", Accept: "application/json"})
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
	var i netdataInfo
	if err := json.Unmarshal(body, &i); err != nil || i.Version == "" {
		return obs, fmt.Errorf("%w: /api/v1/info carries no version (not Netdata?)", ErrNotSupported)
	}
	obs.Version = i.Version
	if i.ReleaseChannel != "" {
		obs.Extra = map[string]string{"releaseChannel": i.ReleaseChannel}
	}
	return obs, nil
}
