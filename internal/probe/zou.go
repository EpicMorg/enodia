// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// zouProbe reads /api/status for the version.
//
// "Kitsu" is the commonly known brand for CG-Wire's production-tracking
// stack, but Kitsu itself is a Vue.js frontend with no version endpoint of
// its own; what actually answers /api/status — confirmed live, including
// on a host literally named "kitsu" in DNS — is Zou, the API backend Kitsu
// talks to. So the product here is "zou", with "kitsu" kept as an alias for
// anyone reaching for the name they actually know the stack by.
type zouProbe struct{}

func (zouProbe) Meta() Meta {
	return Meta{
		Product:       "zou",
		Summary:       "Zou (CG-Wire / Kitsu backend)",
		Aliases:       []string{"kitsu"},
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No DefaultResolver: endoflife.date has no calendar under zou,
		// kitsu or cg-wire (all confirmed 404).
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

func (zouProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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
