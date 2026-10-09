// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// libretranslateProbe reads the API's own OpenAPI document, GET /spec,
// which is public even when API keys are required for translating:
// {"swagger": "2.0", "info": {"title": "LibreTranslate", "version":
// "1.9.6", ...}} (confirmed live on libretranslate/libretranslate:latest,
// whose release was v1.9.6). info.version is the server's version.
type libretranslateProbe struct{}

func (libretranslateProbe) Meta() Meta {
	return Meta{
		Product:         "libretranslate",
		Summary:         "LibreTranslate",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "github", ID: "LibreTranslate/LibreTranslate"},
	}
}

func (libretranslateProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/spec", Accept: "application/json"})
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
	var spec struct {
		Info struct {
			Title   string `json:"title"`
			Version string `json:"version"`
		} `json:"info"`
	}
	if err := json.Unmarshal(body, &spec); err != nil || spec.Info.Title != "LibreTranslate" || spec.Info.Version == "" {
		return obs, fmt.Errorf("%w: /spec is not LibreTranslate's API document", ErrNotSupported)
	}
	obs.Version = spec.Info.Version
	return obs, nil
}
