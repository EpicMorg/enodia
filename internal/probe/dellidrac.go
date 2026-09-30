// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"time"
)

// dellIDRACProbe reads /redfish/v1 for identity, then
// /redfish/v1/Managers/iDRAC.Embedded.1 for the firmware version — two
// requests, not one: confirmed live that iDRAC's own Manager resource
// carries no vendor marker of any kind (no "Manufacturer", no "Oem" key at
// all on a real 12G iDRAC), unlike Supermicro's equivalent resource. The
// vendor signal — "Oem":{"Dell":{...}}, and a "Product": "Integrated Dell
// Remote Access Controller" string alongside it — lives on the service
// root instead. Both requests need credentials: a real 401 was confirmed
// live for each, without them.
//
// "iDRAC.Embedded.1" is the one Manager id checked here — the standard
// Dell convention for the embedded controller across iDRAC generations,
// confirmed on this one real 12G blade; a controller that uses a
// different id (unconfirmed) would need its own fix, not a guess baked in
// ahead of time.
type dellIDRACProbe struct{}

func (dellIDRACProbe) Meta() Meta {
	return Meta{
		Product:       "dell-idrac",
		Summary:       "Dell iDRAC",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthBasic}},
		// No DefaultResolver: BMC firmware is proprietary hardware
		// firmware with no public lifecycle calendar (confirmed 404
		// under dell-idrac/idrac).
	}
}

// dellServiceRoot is the subset of /redfish/v1 this probe needs. Verified
// against a live server's real JSON reply (see
// testdata/dell-idrac_2.65.65.65_root.json).
type dellServiceRoot struct {
	Oem map[string]struct {
		ServiceTag string `json:"ServiceTag"`
	} `json:"Oem"`
}

// dellManager is the subset of /redfish/v1/Managers/iDRAC.Embedded.1 this
// probe needs. Verified against a live server's real JSON reply (see
// testdata/dell-idrac_2.65.65.65_manager.json).
type dellManager struct {
	Model           string `json:"Model"`
	FirmwareVersion string `json:"FirmwareVersion"`
}

func (dellIDRACProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	rootResp, err := FetchHTTP(ctx, t, Request{Path: "/redfish/v1", Accept: "application/json"})
	if err != nil {
		return obs, err
	}
	defer rootResp.Body.Close()
	rootBody, err := ReadBody(rootResp)
	if err != nil {
		return obs, err
	}

	var root dellServiceRoot
	if err := json.Unmarshal(rootBody, &root); err != nil {
		return obs, fmt.Errorf("%w: /redfish/v1 is not valid JSON: %w", ErrUnparseable, err)
	}
	dell, ok := root.Oem["Dell"]
	if !ok {
		return obs, fmt.Errorf("%w: /redfish/v1 carries no Oem.Dell key — not a Dell iDRAC", ErrNotSupported)
	}

	mgrResp, err := FetchHTTP(ctx, t, Request{Path: "/redfish/v1/Managers/iDRAC.Embedded.1", Accept: "application/json"})
	if err != nil {
		return obs, err
	}
	defer mgrResp.Body.Close()
	obs.Endpoint = mgrResp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	mgrBody, err := ReadBody(mgrResp)
	if err != nil {
		return obs, err
	}
	var mgr dellManager
	if err := json.Unmarshal(mgrBody, &mgr); err != nil {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/iDRAC.Embedded.1 is not valid JSON: %w", ErrUnparseable, err)
	}
	if mgr.FirmwareVersion == "" {
		return obs, fmt.Errorf("%w: /redfish/v1/Managers/iDRAC.Embedded.1 response carries no FirmwareVersion", ErrUnparseable)
	}

	obs.Version = mgr.FirmwareVersion
	obs.Extra = map[string]string{}
	if mgr.Model != "" {
		obs.Extra["model"] = mgr.Model
	}
	if dell.ServiceTag != "" {
		obs.Extra["serviceTag"] = dell.ServiceTag
	}
	return obs, nil
}
