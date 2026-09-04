// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// artifactoryProbe reads /artifactory/api/system/version for the version.
//
// Whether this needs credentials varies by instance, confirmed against two
// real servers rather than assumed from one: a fresh
// releases-docker.jfrog.io/jfrog/artifactory-oss install answers 401
// without them, but a real production instance answered 200 anonymously —
// "Allow Anonymous Access" is a real, commonly enabled setting here, not a
// hypothetical. Basic auth with the OSS install's default admin account was
// confirmed to work.
//
// The response body also carries "license", "addons" and "entitlements".
// license is not a fixed literal: on the OSS container it was the harmless
// string "Artifactory OSS", but on the production instance it was a real
// per-install license fingerprint — the kind of value that has no business
// leaving this probe and ending up in stored inventory data, so it and the
// other two fields are deliberately not read here at all.
type artifactoryProbe struct{}

func (artifactoryProbe) Meta() Meta {
	return Meta{
		Product:         "artifactory",
		Summary:         "JFrog Artifactory",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "artifactory"},
	}
}

// artifactoryVersionInfo is the subset of /artifactory/api/system/version
// this probe reads. Verified against a live server's real JSON reply (see
// testdata/artifactory_7.161.20.json) — deliberately not the full shape;
// see the license note on artifactoryProbe.
type artifactoryVersionInfo struct {
	Version  string `json:"version"`
	Revision string `json:"revision"`
}

func (artifactoryProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/artifactory/api/system/version",
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

	var info artifactoryVersionInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /artifactory/api/system/version is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /artifactory/api/system/version response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	if info.Revision != "" {
		obs.Extra = map[string]string{"revision": info.Revision}
	}
	return obs, nil
}
