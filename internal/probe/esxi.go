// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"time"
)

// esxiProbe reads ServiceContent.about via the vSphere API's own
// RetrieveServiceContent discovery call — see vim25.go. Confirmed live
// against a real production ESXi 8.0.3 host, no credentials at all:
// {"apiType":"HostAgent","version":"8.0.3","build":"25067014",
// "fullName":"VMware ESXi 8.0.3 build-25067014",...}.
//
// apiType is checked (D9): a real vCenter answers the identical call with
// apiType=VirtualCenter — see vcenter.go, which runs this same check in
// reverse.
type esxiProbe struct{}

func (esxiProbe) Meta() Meta {
	return Meta{
		Product:         "esxi",
		Summary:         "VMware ESXi",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "esxi"},
	}
}

func (esxiProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	about, err := vim25RetrieveAbout(ctx, t)
	if err != nil {
		return obs, err
	}
	obs.Endpoint = "/sdk"
	obs.DurationMS = time.Since(start).Milliseconds()

	if about.APIType != "HostAgent" {
		return obs, fmt.Errorf("%w: this host reports apiType=%q, not \"HostAgent\" — likely a vCenter Server",
			ErrNotSupported, about.APIType)
	}

	obs.Version = about.Version
	obs.Extra = map[string]string{}
	if about.Build != "" {
		obs.Extra["build"] = about.Build
	}
	return obs, nil
}
