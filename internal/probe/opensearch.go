// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// opensearchProbe reads GET / for the version — the same endpoint and
// shape as elasticsearchProbe, since OpenSearch is a fork of
// Elasticsearch 7.10.2 that kept its root response shape almost
// unchanged. The one field that tells them apart, confirmed live against
// real containers of both: OpenSearch's reply carries
// `version.distribution: "opensearch"` (and a "The OpenSearch Project"
// tagline); a real Elasticsearch's has neither. That check is this
// probe's whole reason to exist as a separate file rather than an alias —
// D9 (product is declared explicitly, probe verifies) means product:
// opensearch pointed at a real Elasticsearch must fail, not silently
// report Elasticsearch's version as OpenSearch's.
//
// Security posture confirmed live to match elasticsearchProbe's exactly:
// a fresh container needs `OPENSEARCH_INITIAL_ADMIN_PASSWORD` set at all
// and answers HTTPS + Basic-auth-required by default; a second container
// with `DISABLE_SECURITY_PLUGIN=true` (a real, documented setting)
// answered the identical request anonymously over plain HTTP.
type opensearchProbe struct{}

func (opensearchProbe) Meta() Meta {
	return Meta{
		Product:         "opensearch",
		Summary:         "OpenSearch",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "opensearch"},
	}
}

// opensearchInfo is the subset of GET / this probe needs. Verified against
// a live server's real JSON reply (see testdata/opensearch_3.8.0.json).
type opensearchInfo struct {
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Distribution  string `json:"distribution"`
		Number        string `json:"number"`
		LuceneVersion string `json:"lucene_version"`
	} `json:"version"`
}

func (opensearchProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/",
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

	var info opensearchInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: GET / is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version.Distribution != "opensearch" {
		return obs, fmt.Errorf("%w: this host reports version.distribution=%q, not \"opensearch\" — likely a plain Elasticsearch",
			ErrNotSupported, info.Version.Distribution)
	}
	if info.Version.Number == "" {
		return obs, fmt.Errorf("%w: GET / response carries no version.number", ErrUnparseable)
	}

	obs.Version = info.Version.Number
	obs.Extra = map[string]string{}
	if info.ClusterName != "" {
		obs.Extra["clusterName"] = info.ClusterName
	}
	if info.Version.LuceneVersion != "" {
		obs.Extra["luceneVersion"] = info.Version.LuceneVersion
	}
	return obs, nil
}
