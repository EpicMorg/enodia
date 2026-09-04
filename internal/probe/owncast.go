// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// owncastProbe reads /api/status for the version.
//
// Neither production instance this probe was initially drafted against was
// reachable: one sits behind a Keycloak-backed OAuth2 Proxy SSO gate (a
// deployment choice, not anything Owncast itself does — out of scope for a
// version probe the same way any other bespoke reverse-proxy login would
// be), the other 404s outright. So the shape was worked out from Owncast's
// own current source first — webserver/handlers/status.go defines the
// field as "versionNumber", not "serverVersion" as an older config once
// assumed; webserver/handlers/generated/generated.gen.go confirms
// GetStatus maps to GET /status, mounted under /api/ (router.go:
// `r.Mount("/api/", handlers.New(h).Handler())`); and
// webserver/handlers/handler.go shows GetStatus is called with no
// auth-requiring middleware wrapper, unlike the routes beside it that
// explicitly wrap with RequireAdminAuth or RequireUserAccessToken — then
// confirmed against a live owncast/owncast:latest container, which
// answered exactly as the source predicted.
type owncastProbe struct{}

func (owncastProbe) Meta() Meta {
	return Meta{
		Product:       "owncast",
		Summary:       "Owncast",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no owncast calendar
		// (confirmed: GET .../api/owncast.json is a 404).
	}
}

// owncastStatus is the subset of /api/status this probe reads. See
// testdata/owncast_0.5.0.json and the source-verification note on
// owncastProbe for where this shape comes from.
type owncastStatus struct {
	VersionNumber string `json:"versionNumber"`
	Online        bool   `json:"online"`
}

func (owncastProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/status",
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

	var info owncastStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.VersionNumber == "" {
		return obs, fmt.Errorf("%w: /api/status response carries no versionNumber", ErrUnparseable)
	}

	obs.Version = info.VersionNumber
	obs.Extra = map[string]string{"online": fmt.Sprintf("%t", info.Online)}
	return obs, nil
}
