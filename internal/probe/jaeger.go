// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// jaegerProbe reads the version the query-service (the UI-serving
// component, port 16686 by default) embeds into its own index.html via
// build-time search/replace — there is no separate version API. Confirmed
// live against a real jaegertracing/all-in-one container:
// `const JAEGER_VERSION = {"gitCommit":"...","gitVersion":"v1.76.0",
// "buildDate":"..."};`. It's a single-page app, so every path (including
// a nonexistent one) serves the identical index.html — confirmed live —
// but "/" is used explicitly rather than relying on that fallback.
//
// Jaeger has no authentication of its own at all; deployments needing
// access control put a reverse proxy or SSO gateway in front of it
// (oauth2-proxy is a common real choice). A target sitting behind one
// answers with a redirect into that gateway's own login flow instead of
// Jaeger's HTML, which this probe (like every probe in this tree) cannot
// complete — the same shape of gap D22 found for Redmine's form login,
// just imposed by the deployment rather than the product itself. That
// case surfaces as this probe's own "no JAEGER_VERSION found" error,
// nothing gateway-specific needed here.
type jaegerProbe struct{}

func (jaegerProbe) Meta() Meta {
	return Meta{
		Product:         "jaeger",
		Summary:         "Jaeger",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "jaeger"},
	}
}

// jaegerVersionPattern captures the JSON object literal assigned to
// JAEGER_VERSION so it can be unmarshaled normally rather than field-by-
// field regexed — unlike phpmyadmin's CommonParams, this one really is
// JSON. Verified against a live server's real "/" reply (see
// testdata/jaeger_1.76.0.html).
var jaegerVersionPattern = regexp.MustCompile(`JAEGER_VERSION\s*=\s*(\{[^}]*\})`)

type jaegerVersionInfo struct {
	GitVersion string `json:"gitVersion"`
}

func (jaegerProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/",
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

	m := jaegerVersionPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no JAEGER_VERSION found in \"/\" "+
			"(either this isn't Jaeger, or a gateway in front of it — an SSO "+
			"proxy, say — answered instead)", ErrNotSupported)
	}

	var info jaegerVersionInfo
	if err := json.Unmarshal(m[1], &info); err != nil {
		return obs, fmt.Errorf("%w: JAEGER_VERSION is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.GitVersion == "" {
		return obs, fmt.Errorf("%w: JAEGER_VERSION.gitVersion is empty "+
			"(this build's version was not stamped in)", ErrUnparseable)
	}

	obs.Version = info.GitVersion
	return obs, nil
}
