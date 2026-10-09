// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// posthogProbe reads self-hosted PostHog's build from its login page.
//
// PostHog no longer ships numbered releases: a self-hosted (hobby)
// install tracks the main branch, and the only identifier it exposes is
// the git commit. The login page embeds
// `window.POSTHOG_APP_CONTEXT = JSON.parse("{...}")` — a JSON document
// inside a JS string literal, quotes escaped as " — whose commit_sha is
// that commit (confirmed live on a production self-hosted instance:
// "55babe9554"; testdata/posthog_55babe9554_login.html keeps the real
// encoding and the relevant keys). The commit is the version; there is no
// lifecycle to compare it with. /_preflight/ is anonymous too but carries
// only service health and the realm ("hosted-clickhouse").
type posthogProbe struct{}

func (posthogProbe) Meta() Meta {
	return Meta{
		Product:       "posthog",
		Summary:       "PostHog (self-hosted; version is the git commit)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
	}
}

var posthogContextPattern = regexp.MustCompile(`POSTHOG_APP_CONTEXT\s*=\s*JSON\.parse\(("(?:[^"\\]|\\.)*")\)`)

type posthogAppContext struct {
	CommitSHA string `json:"commit_sha"`
	Preflight struct {
		Realm string `json:"realm"`
	} `json:"preflight"`
}

func (posthogProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/login", Accept: "text/html"})
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
	m := posthogContextPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no POSTHOG_APP_CONTEXT on /login (not PostHog?)", ErrNotSupported)
	}
	var doc string // the JS string literal is also a JSON string literal
	if err := json.Unmarshal(m[1], &doc); err != nil {
		return obs, fmt.Errorf("%w: POSTHOG_APP_CONTEXT: %w", ErrUnparseable, err)
	}
	var c posthogAppContext
	if err := json.Unmarshal([]byte(doc), &c); err != nil {
		return obs, fmt.Errorf("%w: POSTHOG_APP_CONTEXT: %w", ErrUnparseable, err)
	}
	if c.CommitSHA == "" {
		return obs, fmt.Errorf("%w: POSTHOG_APP_CONTEXT carries no commit_sha", ErrUnparseable)
	}
	obs.Version = c.CommitSHA
	obs.Extra = map[string]string{"commit": c.CommitSHA}
	if c.Preflight.Realm != "" {
		obs.Extra["realm"] = c.Preflight.Realm
	}
	return obs, nil
}
