// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// elasticsearchProbe reads GET / for the version.
//
// Confirmed live against two docker.elastic.co/elasticsearch/elasticsearch
// containers: since 8.0, security (HTTPS plus Basic/Bearer/ApiKey auth) is
// on by default, and an anonymous request to / gets a 401 advertising all
// three schemes. Basic with the elastic superuser (its password reset via
// the image's own elasticsearch-reset-password tool) was confirmed to
// work. A second container started with xpack.security.enabled=false — a
// real, documented setting, not a hypothetical — answered the very same
// request anonymously over plain HTTP with an identical body. Both are
// genuine deployments, so Required stays false and only AuthBasic, the one
// scheme actually exercised, is offered.
//
// D9 (product is declared explicitly, probe verifies): OpenSearch is a
// fork of Elasticsearch 7.10.2 that kept this same GET / shape almost
// unchanged, so without a check this probe would happily report an
// OpenSearch cluster's version as Elasticsearch's. Confirmed live against
// a real opensearchproject/opensearch container that the one reliable
// difference is `version.distribution: "opensearch"`, a field a genuine
// Elasticsearch reply never carries — see opensearch.go, which runs the
// same check in reverse.
type elasticsearchProbe struct{}

func (elasticsearchProbe) Meta() Meta {
	return Meta{
		Product:         "elasticsearch",
		Summary:         "Elasticsearch",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "elasticsearch"},
	}
}

// elasticsearchInfo is the subset of GET / this probe needs. Verified
// against a live server's real JSON reply (see
// testdata/elasticsearch_9.5.3.json).
type elasticsearchInfo struct {
	ClusterName string `json:"cluster_name"`
	Version     struct {
		Distribution  string `json:"distribution"` // "opensearch" on an OpenSearch reply; absent on real Elasticsearch
		Number        string `json:"number"`
		BuildHash     string `json:"build_hash"`
		LuceneVersion string `json:"lucene_version"`
	} `json:"version"`
}

func (elasticsearchProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	var info elasticsearchInfo
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: GET / is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version.Distribution == "opensearch" {
		return obs, fmt.Errorf("%w: this host reports version.distribution=\"opensearch\" — it's OpenSearch, not Elasticsearch", ErrNotSupported)
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
	if info.Version.BuildHash != "" {
		obs.Extra["buildHash"] = info.Version.BuildHash
	}
	return obs, nil
}
