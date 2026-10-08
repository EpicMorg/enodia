// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// rabbitmqProbe reads GET /api/overview from the management plugin's HTTP
// API (port 15672 by default). It is never anonymous: confirmed live
// against rabbitmq:4-management, which answered 401 without credentials
// and, with a management user's Basic credentials, a JSON object whose
// rabbitmq_version is the broker's own version (see
// testdata/rabbitmq_4.3.6_overview.json). The AMQP port itself has no
// pre-auth version exchange worth reading — the management plugin is the
// one place a version is served.
//
// The management API is plain HTTP unless TLS is configured on it, and
// FetchHTTP refuses to send credentials over plain HTTP: an http://
// address needs allow_insecure_transport, deliberately.
type rabbitmqProbe struct{}

func (rabbitmqProbe) Meta() Meta {
	return Meta{
		Product:         "rabbitmq",
		Summary:         "RabbitMQ (management plugin API)",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "rabbitmq"},
	}
}

// rabbitmqOverview is the subset of /api/overview this probe reads.
type rabbitmqOverview struct {
	RabbitMQVersion string `json:"rabbitmq_version"`
	ProductName     string `json:"product_name"`
	ProductVersion  string `json:"product_version"`
	ErlangVersion   string `json:"erlang_version"`
	ClusterName     string `json:"cluster_name"`
}

func (rabbitmqProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/api/overview", Accept: "application/json"})
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
	var o rabbitmqOverview
	if err := json.Unmarshal(body, &o); err != nil {
		return obs, fmt.Errorf("%w: /api/overview is not valid JSON: %w", ErrUnparseable, err)
	}
	if o.RabbitMQVersion == "" {
		return obs, fmt.Errorf("%w: /api/overview carries no rabbitmq_version (not a RabbitMQ management API?)", ErrNotSupported)
	}

	obs.Version = o.RabbitMQVersion
	obs.Extra = map[string]string{}
	for k, v := range map[string]string{"productName": o.ProductName, "productVersion": o.ProductVersion, "erlangVersion": o.ErlangVersion, "clusterName": o.ClusterName} {
		if v != "" {
			obs.Extra[k] = v
		}
	}
	return obs, nil
}
