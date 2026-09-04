// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// teamcityProbe reads /app/rest/server — the entry point TeamCity's own REST
// API reference points at first — for the version.
//
// There is no anonymous access by default: a fresh instance answered 401
// with WWW-Authenticate: Basic and Bearer challenges (guest login is off by
// default), confirmed against a live jetbrains/teamcity-server container
// rather than assumed. Only AuthBasic is offered here: TeamCity's own
// documented superuser pattern — empty username, an access token used as
// the password — was confirmed working this way; the same bootstrap token
// sent as a bare `Authorization: Bearer` was tried too and rejected, even
// though the server advertises Bearer as a supported scheme, so this probe
// does not claim to support it.
type teamcityProbe struct{}

func (teamcityProbe) Meta() Meta {
	return Meta{
		Product:       "teamcity",
		Summary:       "JetBrains TeamCity",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
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

func (teamcityProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/app/rest/server",
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
