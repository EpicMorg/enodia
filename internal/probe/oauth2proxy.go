// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// oauth2ProxyProbe reads the version stamped in /oauth2/sign_in's footer.
// oauth2-proxy has no JSON version endpoint at all; the sign-in page is the
// only anonymous surface (it must render before any session exists), and
// its default template (pkg/app/pagewriter/sign_in.html) writes exactly
// `... OAuth2 Proxy</a> version {{.Version}}</p>` when the deployment hasn't
// overridden it. Confirmed live against a real oauth2-proxy/oauth2-proxy
// container's default page.
//
// The `--footer` flag lets a deployment replace or hide ("-") that whole
// line — no anonymous fallback exists if so, the same shape of problem as
// nginx's server_tokens off (see nginx.go): confirmed product, version
// withheld by the deployment's own config, not this probe's bug.
type oauth2ProxyProbe struct{}

func (oauth2ProxyProbe) Meta() Meta {
	return Meta{
		Product:       "oauth2-proxy",
		Summary:       "oauth2-proxy",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver yet: endoflife.date has no oauth2-proxy
		// calendar today. The user intends to submit one upstream later,
		// alongside teamcity and perforce-swarm (see their own "No
		// DefaultResolver" comments) — wire this up once it exists.
	}
}

// oauth2ProxyFooterPattern matches the sign-in page's default footer line.
// Tied to both the surrounding text and the anchor's link text, not just a
// bare "version X" anywhere on the page, to keep it from matching an
// unrelated page that merely happens to contain those two words.
var oauth2ProxyFooterPattern = regexp.MustCompile(`Secured with <a[^>]*>OAuth2 Proxy</a> version (\S+)</p>`)

func (oauth2ProxyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/oauth2/sign_in",
		Accept: "text/html",
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

	m := oauth2ProxyFooterPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: /oauth2/sign_in has no default footer version line "+
			"(either this isn't oauth2-proxy, or --footer overrides or hides it)", ErrNotSupported)
	}

	obs.Version = string(m[1])
	return obs, nil
}
