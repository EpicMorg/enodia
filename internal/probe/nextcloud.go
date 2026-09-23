// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// nextcloudProbe reads /status.php for the version.
//
// Confirmed live against a live nextcloud container: this endpoint is
// intentionally public — it answered 200 even before setup had run at all
// (installed:false) and again once maintenance mode was turned on via
// `occ maintenance:mode --on` (maintenance:true) — a load-balancer health
// check, not a normal protected route. There is no credentialed path here
// to test or offer, so Auth carries no Kinds.
type nextcloudProbe struct{}

func (nextcloudProbe) Meta() Meta {
	return Meta{
		Product:         "nextcloud",
		Summary:         "Nextcloud",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "nextcloud"},
	}
}

// nextcloudStatus is /status.php's full shape. Verified against a live
// server's real JSON reply (see testdata/nextcloud_34.0.3.json).
//
// versionstring ("34.0.3"), not version ("34.0.3.2"), is what this probe
// reports: it is what endoflife.date's "nextcloud" cycles use for latest,
// confirmed live — version carries an internal fourth build component that
// never appears in the lifecycle calendar and would never compare equal to
// it.
type nextcloudStatus struct {
	Installed      bool   `json:"installed"`
	Maintenance    bool   `json:"maintenance"`
	NeedsDBUpgrade bool   `json:"needsDbUpgrade"`
	Version        string `json:"version"`
	VersionString  string `json:"versionstring"`
	// Edition is "" on a real community server (testdata/
	// nextcloud_34.0.3.json). A pointer keeps "field absent" (older
	// releases) apart from that real empty value.
	Edition *string `json:"edition"`
}

func (nextcloudProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/status.php",
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

	var info nextcloudStatus
	if err := json.Unmarshal(body, &info); err != nil {
		return obs, fmt.Errorf("%w: /status.php is not valid JSON: %w", ErrUnparseable, err)
	}
	if info.VersionString == "" {
		return obs, fmt.Errorf("%w: /status.php response carries no versionstring", ErrUnparseable)
	}

	obs.Version = info.VersionString
	obs.Extra = map[string]string{
		"installed":   fmt.Sprintf("%t", info.Installed),
		"maintenance": fmt.Sprintf("%t", info.Maintenance),
	}
	if info.Version != "" {
		obs.Extra["buildVersion"] = info.Version
	}
	if e, ok := nextcloudEnterprise(info.Edition); ok {
		obs.Extra["enterprise"] = e
	}
	return obs, nil
}

// nextcloudEnterprise maps status.php's edition field onto the
// Extra["enterprise"] convention gitlab and vault share. "" is confirmed
// live to mean the community server; "enterprise" (any case) is what an
// Enterprise subscription is expected to report but has not been seen on
// a real instance, so any other non-empty value is left unreported
// rather than guessed at — an unknown edition keeps every CVE finding,
// a wrong one would hide real ones.
func nextcloudEnterprise(edition *string) (string, bool) {
	switch {
	case edition == nil:
		return "", false
	case *edition == "":
		return "false", true
	case strings.EqualFold(*edition, "enterprise"):
		return "true", true
	default:
		return "", false
	}
}
