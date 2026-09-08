// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// forgejoProbe reads /api/v1/version — a Gitea-API-compatible endpoint
// Forgejo (a Gitea fork) still ships under the same path.
//
// Confirmed live against a real codeberg.org/forgejo/forgejo container:
// anonymous by default (`{"version":"9.0.3+gitea-1.22.0"}`), but an
// instance with `REQUIRE_SIGNIN_VIEW = true` set (a real hardening option,
// confirmed live to apply here too) answers 403 — already ordinary
// ErrAuth via FetchHTTP's existing 401-or-403 handling, nothing
// forgejo-specific needed.
type forgejoProbe struct{}

func (forgejoProbe) Meta() Meta {
	return Meta{
		Product:         "forgejo",
		Summary:         "Forgejo",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic, AuthTokenHeader}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "forgejo"},
	}
}

// forgejoVersionInfo is /api/v1/version's full shape. Verified against a
// live server's real JSON reply (see testdata/forgejo_9.0.3.json).
type forgejoVersionInfo struct {
	Version string `json:"version"`
}

func (forgejoProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v1/version",
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

	var info forgejoVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/v1/version is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/v1/version response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	return obs, nil
}
