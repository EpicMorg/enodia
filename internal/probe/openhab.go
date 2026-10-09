// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// openhabProbe reads the REST API's root, GET /rest/, which openHAB serves
// without a login: {"version": "8", ..., "runtimeInfo": {"version":
// "5.2.2", "buildString": "Release Build"}, "links": [...]} (confirmed live
// on openhab/openhab:latest; the distribution's own version.properties
// said openhab-distro 5.2.2). The top-level "version" is the REST API's;
// runtimeInfo.version is openHAB's. /rest/systeminfo needs a login.
type openhabProbe struct{}

func (openhabProbe) Meta() Meta {
	return Meta{
		Product:       "openhab",
		Summary:       "openHAB",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthBearer, AuthBasic}},
		// No endoflife.date page. openhab-distro publishes milestones
		// ("5.3.0.M2") as ordinary releases; the resolver skips them by name.
		DefaultResolver: ResolverRef{Type: "github", ID: "openhab/openhab-distro"},
	}
}

type openhabRoot struct {
	Version     string `json:"version"`
	RuntimeInfo struct {
		Version     string `json:"version"`
		BuildString string `json:"buildString"`
	} `json:"runtimeInfo"`
}

func (openhabProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/rest/", Accept: "application/json"})
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
	var r openhabRoot
	if err := json.Unmarshal(body, &r); err != nil || r.RuntimeInfo.Version == "" {
		return obs, fmt.Errorf("%w: /rest/ carries no runtimeInfo.version (not openHAB?)", ErrNotSupported)
	}
	obs.Version = r.RuntimeInfo.Version
	obs.Extra = map[string]string{}
	if r.RuntimeInfo.BuildString != "" {
		obs.Extra["build"] = r.RuntimeInfo.BuildString
	}
	if r.Version != "" {
		obs.Extra["restApiVersion"] = r.Version
	}
	return obs, nil
}
