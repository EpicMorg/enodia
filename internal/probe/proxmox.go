// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// proxmoxProbe reads /api2/json/version for the product version.
//
// Proxmox VE requires authentication for this endpoint: an unauthenticated
// request against a live 9.2.2 host replied 401. Two auth shapes exist —
// an API token (a stateless `Authorization: PVEAPIToken=user@realm!tokenid=
// secret` header) or a username/password ticket flow (POST
// /access/ticket, then carry the returned PVEAuthCookie + CSRF token on
// every request). Only the token is supported here: the ticket flow is a
// session-cookie-plus-CSRF login, the same heavier shape D22 already
// rejected for Redmine, and Proxmox's own docs recommend the token for
// exactly this kind of unattended automation anyway. The token is a plain
// `Authorization` header value, so it needs no new AuthKind — it fits
// AuthTokenHeader's existing default-to-Authorization behavior directly.
type proxmoxProbe struct{}

func (proxmoxProbe) Meta() Meta {
	return Meta{
		Product:         "proxmox",
		Summary:         "Proxmox VE",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthTokenHeader}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "proxmox-ve"},
	}
}

// proxmoxVersionInfo is /api2/json/version's real reply shape, confirmed
// live against a Proxmox VE 9.2.2 host:
// {"data":{"release":"9.2","repoid":"...","version":"9.2.2"}}.
type proxmoxVersionInfo struct {
	Data struct {
		Version string `json:"version"`
		Release string `json:"release"`
		RepoID  string `json:"repoid"`
	} `json:"data"`
}

func (proxmoxProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api2/json/version",
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

	var info proxmoxVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: parsing /api2/json/version: %w", ErrUnparseable, err)
	}
	if info.Data.Version == "" {
		return obs, fmt.Errorf("%w: /api2/json/version has no data.version field", ErrUnparseable)
	}

	obs.Version = info.Data.Version
	if info.Data.RepoID != "" {
		obs.Extra = map[string]string{"repoid": info.Data.RepoID}
	}
	return obs, nil
}
