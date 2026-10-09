// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// phpipamProbe reads phpIPAM's version from its login page, anonymously:
// the footer says "phpIPAM IP address management [v1.8.3]", and every
// stylesheet and script is loaded with ?v=1.8.3_r002_v46 — the version, the
// code revision and the database schema version (phpIPAM's own
// SCRIPT_PREFIX). Confirmed live on phpipam/phpipam-www:latest (1.8.3).
// The asset suffix is the fallback when the footer is customised away;
// 1.7.3 (live, on a production instance) loads assets with a bare
// ?v=1.7.3, without the revision and schema parts.
type phpipamProbe struct{}

func (phpipamProbe) Meta() Meta {
	return Meta{
		Product:         "phpipam",
		Summary:         "phpIPAM",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "github", ID: "phpipam/phpipam"},
	}
}

var (
	phpipamFooterPattern = regexp.MustCompile(`phpIPAM IP address management \[v(\d+(?:\.\d+)+)\]`)
	phpipamAssetPattern  = regexp.MustCompile(`\?v=(\d+(?:\.\d+)+)(?:_r(\d+)_v(\d+))?`)
)

func (phpipamProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/index.php?page=login", Accept: "text/html"})
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
	asset := phpipamAssetPattern.FindSubmatch(body)
	if m := phpipamFooterPattern.FindSubmatch(body); m != nil {
		obs.Version = string(m[1])
	} else if asset != nil {
		obs.Version = string(asset[1])
	} else {
		return obs, fmt.Errorf("%w: no phpIPAM footer or ?v= asset version on the login page", ErrNotSupported)
	}
	if asset != nil && len(asset[2]) > 0 {
		obs.Extra = map[string]string{"revision": string(asset[2]), "dbVersion": string(asset[3])}
	}
	return obs, nil
}
