// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// routerosProbe reads /rest/system/resource — MikroTik RouterOS's REST API
// (RouterOS 7.1+; the `www` service, on by default on a fresh install,
// must be enabled). Unlike almost everything else in this tree, there is
// no anonymous path at all: confirmed live against a real CHR (Cloud
// Hosted Router) 7.24.2 VM that this endpoint always answers 401 without
// credentials, and the anonymous webfig login page at "/" carries no
// version text anywhere. This is a router's own admin API, not a web
// app's status page, so requiring credentials is the correct default
// posture, not a hardening option to accommodate.
//
// SSH's banner ("SSH-2.0-ROSSSH", confirmed live) carries no version
// either, ruling out the D10-style banner trick ssh.go and mysql.go use.
type routerosProbe struct{}

func (routerosProbe) Meta() Meta {
	return Meta{
		Product:         "routeros",
		Summary:         "MikroTik RouterOS",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "routeros"},
	}
}

// routerosResourceInfo is the subset of /rest/system/resource this probe
// reads. Verified against a live server's real JSON reply (see
// testdata/routeros_7.24.2.json).
type routerosResourceInfo struct {
	Version      string `json:"version"`
	BoardName    string `json:"board-name"`
	Architecture string `json:"architecture-name"`
}

func (routerosProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/rest/system/resource",
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

	var info routerosResourceInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /rest/system/resource is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /rest/system/resource response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.BoardName != "" {
		obs.Extra["boardName"] = info.BoardName
	}
	if info.Architecture != "" {
		obs.Extra["architecture"] = info.Architecture
	}
	return obs, nil
}
