// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// keycloakProbe reads /admin/serverinfo for the version.
//
// Unlike most other probes here, there is no anonymous path to the version
// at all: confirmed live against a quay.io/keycloak/keycloak container that
// /realms/<realm>/.well-known/openid-configuration (the one endpoint every
// realm always exposes without a token) carries no version field anywhere,
// and /admin/serverinfo — which does — answers 401 without one. A bearer
// access token, obtained the standard OpenID Connect way against the
// realms/master token endpoint, was confirmed live to work. Getting that
// token is outside this probe's job (D10 is about transport, not identity
// federation); the config is expected to hold one already.
type keycloakProbe struct{}

func (keycloakProbe) Meta() Meta {
	return Meta{
		Product:         "keycloak",
		Summary:         "Keycloak",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "keycloak"},
	}
}

// keycloakServerInfo is the subset of /admin/serverinfo this probe needs.
// Verified against a live server's real JSON reply (see
// testdata/keycloak_26.7.3.json).
type keycloakServerInfo struct {
	SystemInfo struct {
		Version     string `json:"version"`
		JavaVersion string `json:"javaVersion"`
	} `json:"systemInfo"`
}

func (keycloakProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/admin/serverinfo",
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

	var info keycloakServerInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /admin/serverinfo is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.SystemInfo.Version == "" {
		return obs, fmt.Errorf("%w: /admin/serverinfo response carries no systemInfo.version", ErrUnparseable)
	}

	obs.Version = info.SystemInfo.Version
	obs.Extra = map[string]string{}
	if info.SystemInfo.JavaVersion != "" {
		obs.Extra["javaVersion"] = info.SystemInfo.JavaVersion
	}
	return obs, nil
}
