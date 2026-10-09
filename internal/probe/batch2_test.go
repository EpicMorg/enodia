// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"testing"
)

// netdata_2.12.1_info.json is a live netdata/netdata:stable's /api/v1/info
// reduced to the keys the probe reads (the rest describes the host).
func TestNetdataProbe(t *testing.T) {
	obs, err := netdataProbe{}.Probe(context.Background(), target(pageServer(t, "/api/v1/info", 200, readFixture(t, "netdata_2.12.1_info.json")), "netdata"))
	if err != nil || obs.Version != "v2.12.1" || obs.Extra["releaseChannel"] == "" {
		t.Fatalf("got %q %+v, %v", obs.Version, obs.Extra, err)
	}
	if _, err := (netdataProbe{}).Probe(context.Background(), target(pageServer(t, "/api/v1/info", 200, []byte(`{}`)), "netdata")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// libretranslate_1.9.6_spec.json is a live container's /spec, paths cut.
func TestLibreTranslateProbe(t *testing.T) {
	obs, err := libretranslateProbe{}.Probe(context.Background(), target(pageServer(t, "/spec", 200, readFixture(t, "libretranslate_1.9.6_spec.json")), "libretranslate"))
	if err != nil || obs.Version != "1.9.6" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
	other := []byte(`{"swagger":"2.0","info":{"title":"Some API","version":"3.0"}}`)
	if _, err := (libretranslateProbe{}).Probe(context.Background(), target(pageServer(t, "/spec", 200, other), "libretranslate")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// "MatriX.146" is what a live TorrServer answered on /echo.
func TestTorrServerProbe(t *testing.T) {
	obs, err := torrserverProbe{}.Probe(context.Background(), target(pageServer(t, "/echo", 200, []byte("MatriX.146")), "torrserver"))
	if err != nil || obs.Version != "MatriX.146" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
	if _, err := (torrserverProbe{}).Probe(context.Background(), target(pageServer(t, "/echo", 200, []byte("<html></html>")), "torrserver")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}
