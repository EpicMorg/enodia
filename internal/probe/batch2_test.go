// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
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

// phpipam_1.8.3_login.html is a live phpipam-www's login page head and
// footer.
func TestPHPIPAMProbe(t *testing.T) {
	srv := pageServer(t, "/index.php", 200, readFixture(t, "phpipam_1.8.3_login.html"))
	obs, err := phpipamProbe{}.Probe(context.Background(), target(srv, "phpipam"))
	if err != nil || obs.Version != "1.8.3" || obs.Extra["revision"] != "002" || obs.Extra["dbVersion"] != "46" {
		t.Fatalf("got %q %+v, %v", obs.Version, obs.Extra, err)
	}
	assetOnly := []byte(`<link href="css/x.css?v=1.7.4_r001_v40">`)
	if obs, err := (phpipamProbe{}).Probe(context.Background(), target(pageServer(t, "/index.php", 200, assetOnly), "phpipam")); err != nil || obs.Version != "1.7.4" {
		t.Fatalf("asset fallback: got %q, %v", obs.Version, err)
	}
	// 1.7.3's assets, as a production instance served them: no _r/_v.
	bare := []byte(`<link href="css/x.css?v=1.7.3">`)
	if obs, err := (phpipamProbe{}).Probe(context.Background(), target(pageServer(t, "/index.php", 200, bare), "phpipam")); err != nil || obs.Version != "1.7.3" || obs.Extra != nil {
		t.Fatalf("bare asset version: got %q %+v, %v", obs.Version, obs.Extra, err)
	}
	if _, err := (phpipamProbe{}).Probe(context.Background(), target(pageServer(t, "/index.php", 200, []byte("<html></html>")), "phpipam")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// domainmod_4.23.0_CHANGELOG.txt is the head of a live container's
// /CHANGELOG.
func TestDomainMODProbe(t *testing.T) {
	obs, err := domainmodProbe{}.Probe(context.Background(), target(pageServer(t, "/CHANGELOG", 200, readFixture(t, "domainmod_4.23.0_CHANGELOG.txt")), "domainmod"))
	if err != nil || obs.Version != "4.23.0" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
	if _, err := (domainmodProbe{}).Probe(context.Background(), target(pageServer(t, "/CHANGELOG", 200, []byte("# Changelog\n## 1.0\n")), "domainmod")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// code-server_4.141.0_login.html is the head of a live
// codercom/code-server's /login.
func TestCodeServerProbe(t *testing.T) {
	obs, err := codeServerProbe{}.Probe(context.Background(), target(pageServer(t, "/login", 200, readFixture(t, "code-server_4.141.0_login.html")), "code-server"))
	if err != nil || obs.Version != "4.141.0" {
		t.Fatalf("got %q, %v", obs.Version, err)
	}
	// code-server_4.92.2_meta.html: the same element from 4.92.2's /login.
	if obs, err := (codeServerProbe{}).Probe(context.Background(), target(pageServer(t, "/login", 200, readFixture(t, "code-server_4.92.2_meta.html")), "code-server")); err != nil || obs.Version != "4.92.2" {
		t.Fatalf("4.92.2: got %q, %v", obs.Version, err)
	}
	if _, err := (codeServerProbe{}).Probe(context.Background(), target(pageServer(t, "/login", 200, []byte("<html></html>")), "code-server")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// splunk_10.6.0.5_server_info.json is splunk/splunk:latest's authenticated
// /services/server/info?output_mode=json, reduced to the keys read.
func TestSplunkProbe(t *testing.T) {
	raw := readFixture(t, "splunk_10.6.0.5_server_info.json")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/services/server/info" || r.URL.Query().Get("output_mode") != "json" {
			t.Errorf("got %s", r.URL)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "admin" || p != "secret" {
			// what splunkd answered without valid credentials, live
			w.Header().Set("Server", "Splunkd")
			w.WriteHeader(http.StatusUnauthorized)
			_, _ = w.Write([]byte(`<?xml version="1.0" encoding="UTF-8"?><response><messages><msg type="ERROR">Unauthorized</msg></messages></response>`))
			return
		}
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	tt := target(srv.URL, "splunk")
	tt.Creds = Credentials{Kind: AuthBasic, Username: "admin", Password: "secret"}
	tt.AllowInsecureTransport = true
	obs, err := splunkProbe{}.Probe(context.Background(), tt)
	if err != nil || obs.Version != "10.6.0.5" || obs.Extra["build"] != "86587d4e3b27" || obs.Extra["license"] != "trial" || obs.Extra["productType"] != "enterprise" {
		t.Fatalf("got %q %+v, %v", obs.Version, obs.Extra, err)
	}
	tt.Creds.Password = "wrong"
	if _, err := (splunkProbe{}).Probe(context.Background(), tt); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestSplunkManagementAddress(t *testing.T) {
	for in, want := range map[string]string{
		"splunk.example.com":             "https://splunk.example.com:8089",
		"https://splunk.example.com":     "https://splunk.example.com:8089",
		"https://splunk.example.com:443": "https://splunk.example.com:443",
		"splunk.example.com:18089":       "splunk.example.com:18089",
	} {
		if got := splunkManagementAddress(in); got != want {
			t.Errorf("splunkManagementAddress(%q) = %q, want %q", in, got, want)
		}
	}
}
