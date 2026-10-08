// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// weblateProbe reads Weblate's version from its own pages, anonymously:
// every page's footer says "Powered by <a href="https://weblate.org/">Weblate
// 2026.10</a>", and its Documentation link points at
// docs.weblate.org/en/weblate-2026.10/ (confirmed live against
// weblate/weblate:latest, see testdata/weblate_2026.10_about.html). The
// REST API's root (/api/) answers anonymously too, but carries no version,
// and /api/metrics/ needs a token. /about/ is read because it exists on
// every Weblate; a site with REQUIRE_LOGIN redirects it to the login page,
// which carries the same footer.
//
// Weblate moved to calendar versions (2026.9, 2026.9.1, 2026.10) after 5.x;
// both shapes parse.
type weblateProbe struct{}

func (weblateProbe) Meta() Meta {
	return Meta{
		Product:       "weblate",
		Summary:       "Weblate",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No endoflife.date page (404). Releases are tagged
		// "weblate-2026.10" on GitHub.
		DefaultResolver: ResolverRef{Type: "github", ID: "WeblateOrg/weblate"},
	}
}

var (
	weblateFooterPattern = regexp.MustCompile(`Powered by <a [^>]*>Weblate (\d+(?:\.\d+)+)</a>`)
	weblateDocsPattern   = regexp.MustCompile(`docs\.weblate\.org/[a-zA-Z_-]+/weblate-(\d+(?:\.\d+)+)/`)
)

func (weblateProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/about/", Accept: "text/html"})
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
	if m := weblateFooterPattern.FindSubmatch(body); m != nil {
		obs.Version = string(m[1])
		return obs, nil
	}
	if m := weblateDocsPattern.FindSubmatch(body); m != nil {
		obs.Version = string(m[1])
		return obs, nil
	}
	return obs, fmt.Errorf("%w: no \"Powered by Weblate\" footer or versioned docs link on /about/", ErrNotSupported)
}
