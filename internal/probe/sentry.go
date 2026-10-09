// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// sentryProbe reads self-hosted Sentry's version from its login page,
// anonymously: the page embeds `window.__initialData = {...}`, whose
// "version" object is {"current": "26.2.1", "latest": ..., "build": "<git
// sha>", ...} (confirmed live against a production self-hosted 26.2.1;
// testdata/sentry_26.2.1_login.html keeps the real keys that matter,
// hostnames replaced). /auth/login/ redirects to the single organization's
// login page, which carries the same data. "latest" is Sentry's own
// upgrade check, stale or empty when that is turned off (it said 21.7.0
// there), so the resolver is used instead. The API root /api/0/ answers
// anonymously but with "version": "0" — the API's, not the server's.
type sentryProbe struct{}

func (sentryProbe) Meta() Meta {
	return Meta{
		Product:       "sentry",
		Summary:       "Sentry (self-hosted)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No endoflife.date page. getsentry/self-hosted's release tags
		// (26.9.0, 26.8.0, ...) are the server versions it installs.
		DefaultResolver: ResolverRef{Type: "github", ID: "getsentry/self-hosted"},
	}
}

var sentryInitialDataPattern = regexp.MustCompile(`(?s)window\.__initialData\s*=\s*(\{.*?\});\s*</script>`)

type sentryInitialData struct {
	Version struct {
		Current string `json:"current"`
		Build   string `json:"build"`
	} `json:"version"`
	SentryMode   string `json:"sentryMode"`
	IsSelfHosted bool   `json:"isSelfHosted"`
}

func (sentryProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/auth/login/", Accept: "text/html"})
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
	m := sentryInitialDataPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no window.__initialData on the login page (not Sentry?)", ErrNotSupported)
	}
	var d sentryInitialData
	if err := json.Unmarshal(m[1], &d); err != nil {
		return obs, fmt.Errorf("%w: window.__initialData is not JSON: %w", ErrUnparseable, err)
	}
	if d.Version.Current == "" {
		return obs, fmt.Errorf("%w: window.__initialData carries no version.current", ErrUnparseable)
	}
	obs.Version = d.Version.Current
	obs.Extra = map[string]string{}
	if d.Version.Build != "" {
		obs.Extra["build"] = d.Version.Build
	}
	if d.SentryMode != "" {
		obs.Extra["mode"] = d.SentryMode
	}
	return obs, nil
}
