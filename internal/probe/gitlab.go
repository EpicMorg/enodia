// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// gitlabProbe reads /api/v4/version for the product version.
//
// GitLab requires authentication for this endpoint by default: an
// unauthenticated request against a live gitlab/gitlab-ce container replied
// 401 with {"message":"401 Unauthorized"}. A personal access token was
// confirmed live to work both as GitLab's native `PRIVATE-TOKEN` header and
// as a bare `Authorization: Bearer` token, so both are offered here — unlike
// TeamCity, where Bearer was tried and rejected.
type gitlabProbe struct{}

func (gitlabProbe) Meta() Meta {
	return Meta{
		Product:         "gitlab",
		Summary:         "GitLab",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthTokenHeader, AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "gitlab"},
	}
}

// gitlabVersionInfo is the subset of /api/v4/version this probe needs.
// Verified against a live server's real JSON reply (see
// testdata/gitlab_19.3.1.json) rather than the API reference alone.
type gitlabVersionInfo struct {
	Version    string `json:"version"`
	Revision   string `json:"revision"`
	Enterprise bool   `json:"enterprise"`
}

func (gitlabProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/v4/version",
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

	var info gitlabVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/v4/version is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/v4/version response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{}
	if info.Revision != "" {
		obs.Extra["revision"] = info.Revision
	}
	obs.Extra["enterprise"] = fmt.Sprintf("%t", info.Enterprise)
	return obs, nil
}
