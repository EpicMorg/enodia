// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// vaultOKStatuses are every status code /v1/sys/health documents itself as
// returning, beyond the plain 200 for "unsealed and active" — each one
// still carries the same JSON body, version included, describing exactly
// why. Sending an X-Vault-Token makes no difference to any of this: the
// endpoint is intentionally anonymous so a load balancer can poll it.
//
// Only 503 (sealed) was reproduced live, against a hashicorp/vault dev
// container sealed via its own /v1/sys/seal API; the rest — 429 (standby),
// 472 (DR secondary), 473 (performance standby), 501 (not initialized) —
// are taken from Vault's own API reference rather than each being forced,
// since they describe cluster topologies a single throwaway container
// can't easily reach.
var vaultOKStatuses = []int{429, 472, 473, 501, 503}

type vaultProbe struct{}

func (vaultProbe) Meta() Meta {
	return Meta{
		Product:         "vault",
		Summary:         "HashiCorp Vault",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "hashicorp-vault"},
	}
}

// vaultHealth is /v1/sys/health's shape. Verified against a live server's
// real JSON reply, unsealed (testdata/vault_2.1.0.json) and sealed
// (testdata/vault_2.1.0_sealed.json).
type vaultHealth struct {
	Version     string `json:"version"`
	Initialized bool   `json:"initialized"`
	Sealed      bool   `json:"sealed"`
	Standby     bool   `json:"standby"`
	ClusterName string `json:"cluster_name"`
}

func (vaultProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:       "/v1/sys/health",
		Accept:     "application/json",
		OKStatuses: vaultOKStatuses,
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

	var info vaultHealth
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /v1/sys/health is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.Version == "" {
		return obs, fmt.Errorf("%w: /v1/sys/health response carries no version", ErrUnparseable)
	}

	obs.Version = info.Version
	obs.Extra = map[string]string{
		"initialized": fmt.Sprintf("%t", info.Initialized),
		"sealed":      fmt.Sprintf("%t", info.Sealed),
		"standby":     fmt.Sprintf("%t", info.Standby),
	}
	if info.ClusterName != "" {
		obs.Extra["clusterName"] = info.ClusterName
	}
	return obs, nil
}
