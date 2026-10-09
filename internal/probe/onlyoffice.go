// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// onlyofficeFamilyProbe covers ONLYOFFICE Docs (Document Server) and its
// Euro-Office fork — the same server, one probe, two products, because
// each follows its own release line (ONLYOFFICE/DocumentServer v9.4.0,
// Euro-Office/DocumentServer v9.3.4 at the time of writing).
//
// The version is read anonymously from the document service's root,
// /index.html, which answers even with JWT enabled: "Server is functioning
// normally. Version: 9.4.0. Build: 129. Release date: ... Package type: 0.
// ..." (confirmed live: onlyoffice/documentserver:latest 9.4.0 build 129,
// and nextcloud/aio-eurooffice 9.3.1 build 37 — whose own package is
// euro-office-documentserver 9.3.1-dev.1, so the number is the real one;
// its release date there is a placeholder). The two answer that page
// identically, so which one it is comes from /welcome/'s title, "ONLYOFFICE
// Docs Community Edition" or "Euro-Office Docs Community Edition". The
// welcome page can be turned off; then the configured product is taken as
// given. A mismatch is refused, naming the product to use, like
// mysql/mariadb (D36).
type onlyofficeFamilyProbe struct {
	product, summary string
	brand            string // as /welcome/'s title spells it
	resolver         ResolverRef
}

func (p onlyofficeFamilyProbe) Meta() Meta {
	return Meta{
		Product:         p.product,
		Summary:         p.summary,
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: p.resolver,
	}
}

var (
	onlyofficeIndexPattern   = regexp.MustCompile(`Version: (\d+(?:\.\d+)+)\. Build: (\d+)\.`)
	onlyofficePackagePattern = regexp.MustCompile(`Package type: (\d+)\.`)
	onlyofficeTitlePattern   = regexp.MustCompile(`<title>\s*([^<]*?) Docs ([A-Za-z]+) Edition\s*</title>`)
)

// onlyofficeBrands is every /welcome/ brand this family knows, by product.
var onlyofficeBrands = map[string]string{"ONLYOFFICE": "onlyoffice", "Euro-Office": "euro-office"}

// onlyofficePackageTypes are the document service's own package types.
var onlyofficePackageTypes = map[string]string{"0": "community", "1": "enterprise", "2": "developer"}

func (p onlyofficeFamilyProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/index.html"})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	body, err := ReadBody(resp)
	if err != nil {
		return obs, err
	}
	m := onlyofficeIndexPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: /index.html has no \"Version: ... Build: ...\" line (not an ONLYOFFICE-family document server?)", ErrNotSupported)
	}
	obs.Version = string(m[1])
	obs.Extra = map[string]string{"build": string(m[2])}
	if pm := onlyofficePackagePattern.FindSubmatch(body); pm != nil {
		if name, ok := onlyofficePackageTypes[string(pm[1])]; ok {
			obs.Extra["edition"] = name
		}
	}

	brand, err := onlyofficeWelcomeBrand(ctx, t)
	if err != nil {
		return obs, err
	}
	if brand != "" {
		obs.Extra["brand"] = brand
		if other, known := onlyofficeBrands[brand]; known && other != p.product {
			return obs, fmt.Errorf("%w: this document server is %s, not %s — use product: %s", ErrNotSupported, brand, p.brand, other)
		}
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// onlyofficeWelcomeBrand reads the brand off /welcome/'s title, or ""
// when the page is turned off (404) or carries no such title.
func onlyofficeWelcomeBrand(ctx context.Context, t Target) (string, error) {
	resp, err := FetchHTTP(ctx, t, Request{Path: "/welcome/", Accept: "text/html"})
	if errors.Is(err, ErrNotSupported) {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ReadBody(resp)
	if err != nil {
		return "", err
	}
	if m := onlyofficeTitlePattern.FindSubmatch(body); m != nil {
		return strings.TrimSpace(string(m[1])), nil
	}
	return "", nil
}
