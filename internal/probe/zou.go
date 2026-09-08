// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// zouFamilyProbe reads /api/status for the version. "Kitsu" is the
// commonly known brand for CG-Wire's production-tracking stack, but Kitsu
// itself is a Vue.js frontend with no version endpoint of its own; what
// actually answers /api/status — confirmed live, including on a host
// literally named "kitsu" in DNS — is Zou, the API backend Kitsu talks to.
//
// "zou" and "kitsu" are registered as two distinct products, not one
// product with an alias, because they need different resolvers: Zou's own
// repo, cgwire/zou, publishes bare git tags only (confirmed live: its
// Releases API returns an empty list), which this project's GitHub
// Releases resolver can't read at all; cgwire/kitsu has real Releases and
// is what a deployment actually named "kitsu" in config strategically
// tracks. The two repos' version numbers do diverge (Zou's backend runs
// ahead of Kitsu's), so `product: zou` stays resolver-less rather than
// comparing against the wrong component's numbers under the more
// technically precise name.
type zouFamilyProbe struct {
	product  string
	summary  string
	resolver ResolverRef // zero value: no resolver at all
}

func (p zouFamilyProbe) Meta() Meta {
	return Meta{
		Product:         p.product,
		Summary:         p.summary,
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: p.resolver,
	}
}

// zouStatus is /api/status's full shape. Verified against a live server's
// real JSON reply (see testdata/zou_1.0.56.json).
type zouStatus struct {
	Name            string `json:"name"`
	Version         string `json:"version"`
	DatabaseUp      bool   `json:"database-up"`
	KeyValueStoreUp bool   `json:"key-value-store-up"`
	EventStreamUp   bool   `json:"event-stream-up"`
	JobQueueUp      bool   `json:"job-queue-up"`
	IndexerUp       bool   `json:"indexer-up"`
}

func (zouFamilyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/api/status",
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

	var info zouStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api/status is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /api/status response carries no version", ErrUnparseable)
	}

	// Vendor identity check, the same reasoning as the atlassian probes:
	// naming the product explicitly in config is supposed to catch a URL
	// pointed at the wrong service.
	if info.Name != "" && info.Name != "Zou" {
		return obs, fmt.Errorf("%w: this host reports name=%q, expected \"Zou\"", ErrNotSupported, info.Name)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{
		"databaseUp":      fmt.Sprintf("%t", info.DatabaseUp),
		"keyValueStoreUp": fmt.Sprintf("%t", info.KeyValueStoreUp),
		"eventStreamUp":   fmt.Sprintf("%t", info.EventStreamUp),
		"jobQueueUp":      fmt.Sprintf("%t", info.JobQueueUp),
		"indexerUp":       fmt.Sprintf("%t", info.IndexerUp),
	}
	return obs, nil
}
