// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// truenasProbe reads /api/v2.0/system/info for the product version.
//
// TrueNAS requires authentication for this endpoint: an unauthenticated
// request against a live 25.10.7 host replied 401. An API key works as a
// plain bearer token — `Authorization: Bearer <key>` — confirmed live, so
// this needs no new AuthKind: AuthBearer already does exactly that.
//
// This superseded an earlier SSH-based version (reading /etc/version,
// since TrueNAS's own /etc/os-release reports the underlying Debian base
// instead of TrueNAS itself) once a real API target became available to
// verify against — this project has no dual-transport-per-product
// fallback mechanism (D2: one product, one probe), so the simpler,
// better-fitting HTTP shape replaces the SSH one outright rather than the
// two coexisting.
type truenasProbe struct{}

func (truenasProbe) Meta() Meta {
	return Meta{
		Product:         "truenas",
		Summary:         "TrueNAS",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "truenas"},
	}
}

// truenasSystemInfo is the subset of /api/v2.0/system/info this probe
// needs. Verified against a live server's real JSON reply (see
// testdata/truenas_25.10.7.json) rather than the API reference alone.
type truenasSystemInfo struct {
	Version string `json:"version"`
}

func (truenasProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v2.0/system/info",
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

	var info truenasSystemInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: parsing /api/v2.0/system/info: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/v2.0/system/info has no version field", ErrUnparseable)
	}

	obs.Version = info.Version
	return obs, nil
}
