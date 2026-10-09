// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// ghostProbe reads GET /ghost/api/admin/site/, the one Admin API endpoint
// Ghost serves without a session or key (the admin app reads it before
// login). Confirmed live against ghost:6: {"site": {..., "version":
// "6.69"}} (see testdata/ghost_6.69_site.json), the same "6.69" its
// <meta name="generator"> and Content-Version header give.
//
// Only major.minor is public. The installed package was 6.69.0; the full
// version is behind the Admin API's signed-JWT key auth, which is not worth
// a new credential kind for one digit — Ghost's releases are x.y.0 almost
// without exception, and "6.69" compares equal to its v6.69.0 tag.
type ghostProbe struct{}

func (ghostProbe) Meta() Meta {
	return Meta{
		Product:       "ghost",
		Summary:       "Ghost",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No endoflife.date page (404).
		DefaultResolver: ResolverRef{Type: "github", ID: "TryGhost/Ghost"},
	}
}

type ghostSite struct {
	Site struct {
		Version string `json:"version"`
		Title   string `json:"title"`
	} `json:"site"`
}

func (ghostProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/ghost/api/admin/site/", Accept: "application/json"})
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
	var s ghostSite
	if err := json.Unmarshal(body, &s); err != nil {
		return obs, fmt.Errorf("%w: /ghost/api/admin/site/ is not JSON (not Ghost?): %w", ErrNotSupported, err)
	}
	if s.Site.Version == "" {
		return obs, fmt.Errorf("%w: /ghost/api/admin/site/ carries no site.version", ErrNotSupported)
	}
	obs.Version = s.Site.Version
	return obs, nil
}
