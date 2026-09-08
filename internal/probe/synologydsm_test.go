// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

// synology-dsm_7.3.2-86009.json is a real SYNO.DSM.Info reply captured
// from a live DSM 7.3.2 NAS (serial scrubbed; every other field is real).
func loadSynologyFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "synology-dsm_7.3.2-86009.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// synologyTestServer fakes the two-call flow this probe performs:
// SYNO.API.Auth login (real shape confirmed live: {"data":{"sid":...,
// "synotoken":...},"success":true}), then SYNO.DSM.Info gated on both the
// sid and, when requireToken is true, the SynoToken query param too —
// confirmed live that a real DSM instance with CSRF protection enabled
// rejects a request carrying only _sid with error code 119.
func synologyTestServer(t *testing.T, infoFixture []byte, requireToken bool) string {
	t.Helper()
	const wantAccount = "probeuser"
	const wantPasswd = "probepass"
	const sid = "test-sid"
	const token = "test-token"

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		w.Header().Set("Content-Type", "application/json")
		switch q.Get("api") {
		case "SYNO.API.Auth":
			switch q.Get("method") {
			case "login":
				if q.Get("account") != wantAccount || q.Get("passwd") != wantPasswd {
					_, _ = w.Write([]byte(`{"success":false,"error":{"code":400}}`))
					return
				}
				_, _ = w.Write([]byte(`{"success":true,"data":{"sid":"` + sid + `","synotoken":"` + token + `"}}`))
			case "logout":
				_, _ = w.Write([]byte(`{"success":true}`))
			default:
				t.Errorf("unexpected SYNO.API.Auth method %q", q.Get("method"))
			}
		case "SYNO.DSM.Info":
			if q.Get("_sid") != sid || (requireToken && q.Get("SynoToken") != token) {
				_, _ = w.Write([]byte(`{"success":false,"error":{"code":119}}`))
				return
			}
			_, _ = w.Write(infoFixture)
		default:
			t.Errorf("unexpected api %q", q.Get("api"))
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func TestSynologyDSMProbeParsesRealFixture(t *testing.T) {
	addr := synologyTestServer(t, loadSynologyFixture(t), true)

	p := synologyDSMProbe{}
	tgt := target(addr, "synology-dsm")
	tgt.Creds = Credentials{Kind: AuthPassword, Username: "probeuser", Password: "probepass"}
	tgt.AllowInsecureTransport = true

	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.3.2-86009" {
		t.Fatalf("got version %q", obs.Version)
	}
}

// Confirmed live: a DSM instance without CSRF protection accepts _sid
// alone, so the probe must work in that shape too, not only the
// SynoToken-required one.
func TestSynologyDSMProbeWorksWithoutTokenRequirement(t *testing.T) {
	addr := synologyTestServer(t, loadSynologyFixture(t), false)

	p := synologyDSMProbe{}
	tgt := target(addr, "synology-dsm")
	tgt.Creds = Credentials{Kind: AuthPassword, Username: "probeuser", Password: "probepass"}
	tgt.AllowInsecureTransport = true

	obs, err := p.Probe(context.Background(), tgt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.3.2-86009" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestSynologyDSMProbeWrongPasswordIsErrAuth(t *testing.T) {
	addr := synologyTestServer(t, loadSynologyFixture(t), true)

	p := synologyDSMProbe{}
	tgt := target(addr, "synology-dsm")
	tgt.Creds = Credentials{Kind: AuthPassword, Username: "probeuser", Password: "wrong"}
	tgt.AllowInsecureTransport = true

	_, err := p.Probe(context.Background(), tgt)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSynologyDSMProbeNoCredentialsIsErrAuth(t *testing.T) {
	p := synologyDSMProbe{}
	tgt := target("http://127.0.0.1:1", "synology-dsm")

	_, err := p.Probe(context.Background(), tgt)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSynologyDSMProbeMeta(t *testing.T) {
	m := synologyDSMProbe{}.Meta()
	if m.Product != "synology-dsm" {
		t.Fatalf("got product %q", m.Product)
	}
	if !m.Auth.Required {
		t.Fatal("synology-dsm requires authentication")
	}
	if !m.Auth.Accepts(AuthPassword) {
		t.Fatal("expected password auth to be accepted")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (endoflife.date has no DSM calendar)", m.DefaultResolver)
	}
}
