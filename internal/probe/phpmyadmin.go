// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// phpmyadminProbe reads the version out of the login page's own
// `CommonParams.setAll({...})` bootstrap call — phpMyAdmin's JS uses this
// object for every AJAX request it makes, so it ships on every page,
// authenticated or not, with no separate version endpoint needed. The same
// value also appears dozens of times as a `?v=5.2.3` cache-busting suffix
// on every static asset URL on the page, but the bootstrap call is a
// single, unambiguous occurrence.
//
// Confirmed live against a real phpmyadmin/phpmyadmin container.
type phpmyadminProbe struct{}

func (phpmyadminProbe) Meta() Meta {
	return Meta{
		Product:         "phpmyadmin",
		Summary:         "phpMyAdmin",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "phpmyadmin"},
	}
}

// phpmyadminVersionPattern matches CommonParams.setAll's own version field.
// Verified against a live server's real "/" reply (see
// testdata/phpmyadmin_5.2.3.html) — a JS object literal with unquoted
// keys, not JSON, so this is a text match rather than a json.Unmarshal.
var phpmyadminVersionPattern = regexp.MustCompile(`CommonParams\.setAll\(\{[^}]*\bversion:"([^"]+)"`)

func (phpmyadminProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	m := phpmyadminVersionPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no CommonParams.setAll version field found "+
			"(either this isn't phpMyAdmin, or the page changed shape)", ErrNotSupported)
	}

	obs.Version = string(m[1])
	return obs, nil
}
