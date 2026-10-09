// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/url"
	"strings"
	"time"
)

// splunkProbe reads GET /services/server/info?output_mode=json from
// splunkd's management port (8089), which needs credentials: a Splunk
// user over Basic, or a Splunk authentication token as Bearer. Without
// them splunkd answers 401 with an XML "Unauthorized" and "Server:
// Splunkd" — confirmed live on a production 9.4.1 and on
// splunk/splunk:latest (10.6.0.5), whose authenticated reply is the
// fixture (testdata/splunk_10.6.0.5_server_info.json, reduced to the keys
// read). The web UI (8000) is often behind a reverse proxy or CDN that
// rewrites or challenges it, and its login page carries no version worth
// relying on. An address without a port gets 8089.
type splunkProbe struct{}

func (splunkProbe) Meta() Meta {
	return Meta{
		Product:         "splunk",
		Summary:         "Splunk Enterprise (splunkd management API)",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic, AuthBearer}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "splunk"},
	}
}

const splunkManagementPort = "8089"

type splunkServerInfo struct {
	Entry []struct {
		Content struct {
			Version     string `json:"version"`
			Build       string `json:"build"`
			ProductType string `json:"product_type"`
			IsFree      bool   `json:"isFree"`
			IsTrial     bool   `json:"isTrial"`
		} `json:"content"`
	} `json:"entry"`
}

// splunkManagementAddress adds splunkd's port to an address that has none.
func splunkManagementAddress(addr string) string {
	raw := addr
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Port() != "" {
		return addr
	}
	u.Host = net.JoinHostPort(u.Hostname(), splunkManagementPort)
	return u.String()
}

func (splunkProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	t.Address = splunkManagementAddress(t.Address)
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/services/server/info?output_mode=json", Accept: "application/json"})
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
	var info splunkServerInfo
	if err := json.Unmarshal(body, &info); err != nil || len(info.Entry) == 0 || info.Entry[0].Content.Version == "" {
		return obs, fmt.Errorf("%w: /services/server/info carries no version (not splunkd's management port?)", ErrNotSupported)
	}
	c := info.Entry[0].Content
	obs.Version = c.Version
	obs.Extra = map[string]string{}
	if c.Build != "" {
		obs.Extra["build"] = c.Build
	}
	switch {
	case c.IsFree:
		obs.Extra["license"] = "free"
	case c.IsTrial:
		obs.Extra["license"] = "trial"
	}
	if c.ProductType != "" {
		obs.Extra["productType"] = c.ProductType
	}
	return obs, nil
}
