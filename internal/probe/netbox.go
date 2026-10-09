// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// netboxProbe reads NetBox's version from its login page, anonymously:
// the root element carries data-netbox-version="4.3.3-Docker-3.3.0" and
// the bundle is loaded as /static/netbox.js?v=4.3.3 (confirmed live on a
// production NetBox from netbox-docker; testdata/netbox_4.3.3_login.html
// keeps those parts). The "-Docker-3.3.0" suffix is netbox-docker's image
// version and goes into extra. The REST API (/api/status/) needs a token.
type netboxProbe struct{}

func (netboxProbe) Meta() Meta {
	return Meta{
		Product:       "netbox",
		Summary:       "NetBox",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// No endoflife.date page.
		DefaultResolver: ResolverRef{Type: "github", ID: "netbox-community/netbox"},
	}
}

var (
	netboxDataVersionPattern = regexp.MustCompile(`data-netbox-version="([^"]+)"`)
	netboxAssetPattern       = regexp.MustCompile(`/static/netbox\.js\?v=(\d+(?:\.\d+)+)`)
)

func (netboxProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/login/", Accept: "text/html"})
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
	if m := netboxDataVersionPattern.FindSubmatch(body); m != nil {
		version, docker, _ := strings.Cut(string(m[1]), "-Docker-")
		obs.Version = version
		if docker != "" {
			obs.Extra = map[string]string{"netboxDocker": docker}
		}
		return obs, nil
	}
	if m := netboxAssetPattern.FindSubmatch(body); m != nil {
		obs.Version = string(m[1])
		return obs, nil
	}
	return obs, fmt.Errorf("%w: no data-netbox-version or netbox.js?v= on /login/ (not NetBox?)", ErrNotSupported)
}
