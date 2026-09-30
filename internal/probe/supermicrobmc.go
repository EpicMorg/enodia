// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// supermicroBMCProbe reads GET /redfish/v1/Managers/1 for the BMC's own
// firmware version — a real 401 confirmed live without credentials, on
// both hosts tested.
//
// Confirmed live against two real Supermicro BMCs of different
// generations: an X12-series board on the current AST2600 BMC chip
// (firmware "01.05.25") and an older X9/X10-era board on a plain
// "ASPEED"-branded BMC (firmware "01.73.13"). Neither carries a top-level
// "Manufacturer" or "Vendor" field anywhere in its Redfish tree that this
// one request can see — the older board has none at all, even on
// /redfish/v1/ itself. What both share, confirmed live on this exact
// resource: an "Oem":{"Supermicro":{...}} key, present even though its
// own contents differ by generation (RADIUS/NTP/etc. live at different
// sub-paths). That's the D9 signal this probe checks, not a field that
// only one of the two generations actually has.
type supermicroBMCProbe struct{}

func (supermicroBMCProbe) Meta() Meta {
	return Meta{
		Product:       "supermicro-bmc",
		Summary:       "Supermicro BMC",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic}},
		// No DefaultResolver: BMC firmware is proprietary hardware
		// firmware with no public lifecycle calendar (confirmed 404
		// under supermicro/supermicro-bmc).
	}
}

// supermicroManager is the subset of /redfish/v1/Managers/1 this probe
// needs. Verified against two live servers' real JSON replies (see
// testdata/supermicro-bmc_01.05.25.json and _01.73.13.json).
type supermicroManager struct {
	Model           string                     `json:"Model"`
	FirmwareVersion string                     `json:"FirmwareVersion"`
	Oem             map[string]json.RawMessage `json:"Oem"`
}

func (supermicroBMCProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/redfish/v1/Managers/1",
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

	var mgr supermicroManager
	if err := json.Unmarshal(body, &mgr); err != nil {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/1 is not valid JSON: %w", ErrUnparseable, err)
	}
	if _, ok := mgr.Oem["Supermicro"]; !ok {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/1 carries no Oem.Supermicro key — not a Supermicro BMC", ErrNotSupported)
	}
	if mgr.FirmwareVersion == "" {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/1 response carries no FirmwareVersion", ErrUnparseable)
	}

	obs.Version = mgr.FirmwareVersion
	obs.Extra = map[string]string{}
	if mgr.Model != "" {
		obs.Extra["model"] = mgr.Model
	}
	return obs, nil
}
