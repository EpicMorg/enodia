// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"time"
)

// vcenterProbe reads ServiceContent.about via the vSphere API's own
// RetrieveServiceContent discovery call — see vim25.go, shared with
// esxiProbe.
//
// Confirmed live against a real production vCenter 8.0.3 instance, no
// credentials at all: {"apiType":"VirtualCenter","version":"8.0.3",
// "build":"25092719","fullName":"VMware vCenter Server 8.0.3
// build-25092719",...} — apiType is the field that distinguishes it from
// an ESXi host's identical-shaped reply (D9; see esxiProbe, which runs
// this same check in reverse). This replaced an earlier version of this
// probe that read /sdk/vimServiceVersions.xml instead: that endpoint
// answers identically for ESXi and vCenter alike, so it could never tell
// the two apart, and it reports vim25's own API schema version (e.g.
// "8.0.3.0") rather than the product's real marketing version.
type vcenterProbe struct{}

func (vcenterProbe) Meta() Meta {
	return Meta{
		Product:         "vcenter",
		Summary:         "VMware vCenter Server",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "vcenter"},
	}
}

func (vcenterProbe) Probe(ctx context.Context, t Target) (Observation, error) {
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

	if about.APIType != "VirtualCenter" {
		return obs, fmt.Errorf("%w: this host reports apiType=%q, not \"VirtualCenter\" — likely an ESXi host",
			ErrNotSupported, about.APIType)
	}

	obs.Version = about.Version
	obs.Extra = map[string]string{}
	if about.Build != "" {
		obs.Extra["build"] = about.Build
	}
	return obs, nil
}
