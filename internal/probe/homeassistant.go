// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// homeAssistantProbe reads GET /api/config with a long-lived access token
// (Profile > Security > Long-lived access tokens), the documented way to
// call Home Assistant's REST API. Nothing anonymous carries the version:
// /api/ and /api/config answered 401, and /manifest.json and the
// onboarding endpoints have none (confirmed live on
// ghcr.io/home-assistant/home-assistant:stable 2026.10.0). /api/config
// also returns the home's coordinates, paths and URLs; only version,
// state and safe/recovery mode are read (the fixture keeps just those).
type homeAssistantProbe struct{}

func (homeAssistantProbe) Meta() Meta {
	return Meta{
		Product:       "home-assistant",
		Aliases:       []string{"homeassistant"},
		Summary:       "Home Assistant (REST API, long-lived token)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthBearer}},
		// No endoflife.date page.
		DefaultResolver: ResolverRef{Type: "github", ID: "home-assistant/core"},
	}
}

type haConfig struct {
	Version      string `json:"version"`
	State        string `json:"state"`
	SafeMode     bool   `json:"safe_mode"`
	RecoveryMode bool   `json:"recovery_mode"`
}

func (homeAssistantProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/api/config", Accept: "application/json"})
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
	var c haConfig
	if err := json.Unmarshal(body, &c); err != nil || c.Version == "" {
		return obs, fmt.Errorf("%w: /api/config carries no version (not Home Assistant?)", ErrNotSupported)
	}
	obs.Version = c.Version
	obs.Extra = map[string]string{}
	if c.State != "" {
		obs.Extra["state"] = c.State
	}
	if c.SafeMode || c.RecoveryMode {
		obs.Extra["recoveryMode"] = "true"
	}
	return obs, nil
}
