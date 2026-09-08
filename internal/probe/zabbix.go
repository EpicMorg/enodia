// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// zabbixProbe calls the JSON-RPC apiinfo.version method, the one method in
// Zabbix's API explicitly documented to need no authentication — everything
// else requires a session token this probe has no reason to hold.
//
// The endpoint only answers POST with a JSON body; a bare GET was confirmed
// live to get HTTP 412 (Precondition Failed), not a version. "Content-Type:
// application/json" (rather than the API reference's own "application/
// json-rpc") was also confirmed live to be accepted.
type zabbixProbe struct{}

func (zabbixProbe) Meta() Meta {
	return Meta{
		Product:         "zabbix",
		Summary:         "Zabbix",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "zabbix"},
	}
}

// zabbixRPCResponse is the JSON-RPC envelope apiinfo.version replies with.
// Verified against a live, internet-facing Zabbix frontend (see
// testdata/zabbix_7.4.10.json) rather than the API reference alone.
type zabbixRPCResponse struct {
	Result string `json:"result"`
	Error  *struct {
		Message string `json:"message"`
		Data    string `json:"data"`
	} `json:"error"`
}

func (zabbixProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:    "/api_jsonrpc.php",
		Method:  http.MethodPost,
		Accept:  "application/json",
		Body:    []byte(`{"jsonrpc":"2.0","method":"apiinfo.version","params":{},"id":1}`),
		Headers: map[string]string{"Content-Type": "application/json"},
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

	var info zabbixRPCResponse
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /api_jsonrpc.php is not valid JSON-RPC: %w", ErrUnparseable, err)
	}
	if info.Error != nil {
		return obs, fmt.Errorf("%w: apiinfo.version: %s", ErrUnparseable, info.Error.Message)
	}
	if info.Result == "" {
		return obs, fmt.Errorf("%w: apiinfo.version reply carries no result", ErrUnparseable)
	}

	obs.Version = info.Result
	return obs, nil
}
