// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// haproxyProbe reads the version out of the stats page's own heading.
//
// HAProxy has no version endpoint and, unlike nginx, sets no Server header
// identifying itself at all by default — confirmed live against a real
// haproxy:3.0 container. The stats page (`stats enable` in the config; not
// on by default) is the only anonymous surface, and only its HTML form
// carries the version: the `;csv` stats export was confirmed live to have
// no version column anywhere in its ~140-column header.
//
// `stats auth user:pass` (HAProxy's own config directive for this page) is
// ordinary HTTP Basic, which FetchHTTP already handles the same as any
// other probe — a target with that configured just needs credentials.
type haproxyProbe struct{}

func (haproxyProbe) Meta() Meta {
	return Meta{
		Product:         "haproxy",
		Summary:         "HAProxy",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "haproxy"},
	}
}

// haproxyStatsVersionPattern matches the stats page's <h1> heading:
// `HAProxy version 3.0.27-a2b09cd, released 2026/08/27`. Verified against a
// live server's real HTML reply (see testdata/haproxy_3.0.27.html).
var haproxyStatsVersionPattern = regexp.MustCompile(`HAProxy version (\S+),`)

func (haproxyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/stats",
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

	m := haproxyStatsVersionPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no \"HAProxy version ...\" heading found "+
			"(either the stats page isn't at this path, or this isn't HAProxy)", ErrNotSupported)
	}

	obs.Version = string(m[1])
	return obs, nil
}
