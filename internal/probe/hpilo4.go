// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// hpILO4Probe reads GET /redfish/v1/Managers/1/ for the controller's own
// firmware version — a real 401 confirmed live without credentials.
//
// iLO 4 predates HPE's move to standard Redfish: its own service root
// calls itself "HP RESTful Root Service" with non-standard @odata.type
// values ("#ServiceRoot.1.0.0.ServiceRoot", not the versioned
// "#ServiceRoot.v1_x_x.ServiceRoot" shape genuine Redfish uses), confirmed
// live. The resource paths and field names this probe actually reads
// happen to overlap with real Redfish closely enough that the same
// FetchHTTP/JSON approach works unchanged — this is specifically iLO 4's
// shape, not assumed to also hold for iLO 5, which is fully Redfish-
// compliant and was not available to confirm live; that would need its
// own probe (and likely its own product id) once it can be.
type hpILO4Probe struct{}

func (hpILO4Probe) Meta() Meta {
	return Meta{
		Product:       "hp-ilo4",
		Summary:       "HP iLO 4",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic}},
		// No DefaultResolver: BMC firmware is proprietary hardware
		// firmware with no public lifecycle calendar (confirmed 404
		// under ilo/hp-ilo).
	}
}

// hpILOManager is the subset of /redfish/v1/Managers/1/ this probe needs.
// Verified against a live server's real JSON reply (see
// testdata/hp-ilo4_2.82.json).
type hpILOManager struct {
	FirmwareVersion string                     `json:"FirmwareVersion"`
	Oem             map[string]json.RawMessage `json:"Oem"`
}

// hpILOVersionPattern extracts the firmware revision ("2.82") out of
// FirmwareVersion's real shape, "iLO 4 v2.82" — confirmed live. The
// generation ("4") isn't reported as the version: this probe is already
// scoped to iLO 4 by product id, and reporting "4.2.82" would make every
// iLO 4 controller's major version identical, hiding the number that
// actually distinguishes one firmware release from another.
var hpILOVersionPattern = regexp.MustCompile(`v(\d+(?:\.\d+)*)`)

func (hpILO4Probe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/redfish/v1/Managers/1/",
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

	var mgr hpILOManager
	if err := json.Unmarshal(body, &mgr); err != nil {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/1/ is not valid JSON: %w", ErrUnparseable, err)
	}
	if _, ok := mgr.Oem["Hp"]; !ok {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/1/ carries no Oem.Hp key — not an HP iLO", ErrNotSupported)
	}

	m := hpILOVersionPattern.FindStringSubmatch(mgr.FirmwareVersion)
	if m == nil {
		return obs, fmt.Errorf("%w: FirmwareVersion %q is not a recognized \"iLO 4 vX.YY\" string", ErrUnparseable, mgr.FirmwareVersion)
	}

	obs.Version = m[1]
	obs.Extra = map[string]string{"raw": mgr.FirmwareVersion}
	return obs, nil
}
