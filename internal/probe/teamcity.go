// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// teamcityProbe reads the server version over TeamCity's REST API.
//
// Without credentials it reads /app/rest/server/version, which TeamCity
// serves to anyone: confirmed live against fresh jetbrains/teamcity-server
// containers 2017.2.4, 2018.2.4, 2019.2.4, 2020.2.4, 2024.03 and 2026.1.1
// with no administrator and guest login off (guest-only endpoints such as
// /guestAuth/app/rest/projects answered 401 there), and against seven
// production instances. The reply is plain text, "2026.1.1 (build 222577)".
//
// With credentials it reads /app/rest/server instead — the entry point
// TeamCity's own REST API reference points at first, which also carries
// internalId. That one is never anonymous: a fresh instance answered 401
// with WWW-Authenticate: Basic and Bearer challenges.
//
// Both AuthBasic and AuthBearer are offered, because TeamCity has two
// distinct kinds of token with opposite behavior, both confirmed live:
//   - The one-time superuser bootstrap token a fresh server logs on first
//     start only works as Basic (empty username, the token as password) —
//     the same bootstrap token sent as a bare `Authorization: Bearer` was
//     tried against a fresh container and rejected.
//   - A normal user's personal access token (Profile > Access Tokens, the
//     way real long-lived automation actually authenticates) is the
//     opposite: confirmed against seven real production instances, it
//     works as `Authorization: Bearer` and is flatly rejected as Basic —
//     "Incorrect username or password" even with an empty username. An
//     earlier version of this probe generalized from the bootstrap-token
//     case alone and refused to offer Bearer at all, which would have
//     rejected the credential shape real deployments actually use.
type teamcityProbe struct{}

func (teamcityProbe) Meta() Meta {
	return Meta{
		Product:       "teamcity",
		Summary:       "JetBrains TeamCity",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic, AuthBearer}},
		// No DefaultResolver: endoflife.date has no teamcity calendar
		// (confirmed: GET .../api/teamcity.json is a 404).
	}
}

// teamcityServerInfo is the subset of /app/rest/server this probe needs.
// Verified against a live server's real JSON reply (see
// testdata/teamcity_2026.2.json) rather than the REST reference alone.
type teamcityServerInfo struct {
	Version      string `json:"version"` // full string, e.g. "2026.2 (build 238924)"
	VersionMajor int    `json:"versionMajor"`
	VersionMinor int    `json:"versionMinor"`
	BuildNumber  string `json:"buildNumber"`
	InternalID   string `json:"internalId"`
}

// teamcityVersionPattern is /app/rest/server/version's whole reply. It
// also keeps a 200 HTML page — what TeamCity serves on every path while it
// is still starting up — from being taken for a version.
var teamcityVersionPattern = regexp.MustCompile(`^(\d{4}\.\d+(?:\.\d+)* \(build (\d+)\))$`)

func (teamcityProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	anonymous := t.Creds.IsZero()
	req := Request{Path: "/app/rest/server", Accept: "application/json"}
	if anonymous {
		req = Request{Path: "/app/rest/server/version", Accept: "text/plain"}
	}
	resp, err := FetchHTTP(ctx, t, req)
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

	if anonymous {
		m := teamcityVersionPattern.FindStringSubmatch(strings.TrimSpace(string(body)))
		if m == nil {
			return obs, fmt.Errorf("%w: /app/rest/server/version is not a TeamCity version string", ErrUnparseable)
		}
		obs.Version = m[1]
		obs.Extra = map[string]string{"buildNumber": m[2]}
		return obs, nil
	}

	var info teamcityServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /app/rest/server is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /app/rest/server response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.BuildNumber != "" {
		obs.Extra["buildNumber"] = info.BuildNumber
	}
	if info.InternalID != "" {
		obs.Extra["internalId"] = info.InternalID
	}
	return obs, nil
}
