// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// traefikProbe reads /api/version.
//
// Confirmed live against a real traefik:v3.1 container: with the API router
// enabled at all (off by default — neither --api nor --api.insecure is set
// on a stock instance), this endpoint needs no credentials under
// --api.insecure=true. A deployment that instead wires the API router to an
// entrypoint behind its own BasicAuth/DigestAuth middleware (the documented
// "secure" way to expose it) answers with ordinary HTTP Basic challenges,
// which AuthBasic already covers the same as any other probe. An instance
// with the API not enabled at all answers 404 here, indistinguishable from
// a wrong address — both correctly become ErrNotSupported via FetchHTTP's
// existing 404 handling, no special-casing needed.
type traefikProbe struct{}

func (traefikProbe) Meta() Meta {
	return Meta{
		Product:         "traefik",
		Summary:         "Traefik",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "traefik"},
	}
}

// traefikVersionInfo is /api/version's full shape (Codename and startDate
// are not read — they describe the release, not the deployment). Verified
// against a live server's real JSON reply (see testdata/traefik_3.1.7.json).
type traefikVersionInfo struct {
	Version string `json:"Version"`
}

func (traefikProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	var info traefikVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/version is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/version response carries no Version", ErrUnparseable)
	}

	obs.Version = info.Version
	return obs, nil
}
