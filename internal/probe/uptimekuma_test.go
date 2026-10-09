// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// kumaReplayServer answers each Engine.IO poll (GET) with the next recorded
// response body from a live Uptime Kuma's transcript, and every POST with
// "ok", as the real server does. posts collects the POST bodies.
func kumaReplayServer(t *testing.T, fixture string) (string, func() []string) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var gets []string
	if err := json.Unmarshal(raw, &gets); err != nil {
		t.Fatalf("fixture: %v", err)
	}
	var mu sync.Mutex
	var posts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/socket.io/" || r.URL.Query().Get("EIO") != "4" {
			t.Errorf("got %s", r.URL)
		}
		mu.Lock()
		defer mu.Unlock()
		if r.Method == http.MethodPost {
			b, _ := io.ReadAll(r.Body)
			posts = append(posts, string(b))
			_, _ = w.Write([]byte("ok"))
			return
		}
		if len(gets) == 0 {
			http.Error(w, "session closed", http.StatusBadRequest)
			return
		}
		_, _ = w.Write([]byte(gets[0]))
		gets = gets[1:]
	}))
	t.Cleanup(srv.Close)
	return srv.URL, func() []string { mu.Lock(); defer mu.Unlock(); return append([]string(nil), posts...) }
}

func kumaTarget(addr string) Target {
	tt := target(addr, "uptime-kuma")
	tt.Creds = Credentials{Kind: AuthPassword, Username: "admin", Password: "secret"}
	tt.AllowInsecureTransport = true // httptest is plain HTTP
	return tt
}

func TestUptimeKumaProbeLogin(t *testing.T) {
	for fixture, want := range map[string]string{
		"uptime-kuma_1.23.17_login.json": "1.23.17", // ack, then the versioned info
		"uptime-kuma_2.5.5_login.json":   "2.5.5",   // versioned info before the ack
	} {
		addr, posts := kumaReplayServer(t, fixture)
		obs, err := uptimeKumaProbe{}.Probe(context.Background(), kumaTarget(addr))
		if err != nil {
			t.Fatalf("%s: Probe: %v", fixture, err)
		}
		if obs.Version != want || obs.Extra["latestVersion"] != "2.5.5" {
			t.Fatalf("%s: got %q %+v", fixture, obs.Version, obs.Extra)
		}
		p := posts()
		if len(p) < 2 || p[0] != "40" || !strings.HasPrefix(p[1], `420["login",`) || !strings.Contains(p[1], `"username":"admin"`) {
			t.Fatalf("%s: posts %q", fixture, p)
		}
	}
}

func TestUptimeKumaProbeBadPasswordIsErrAuth(t *testing.T) {
	addr, _ := kumaReplayServer(t, "uptime-kuma_1.23.17_badlogin.json")
	if _, err := (uptimeKumaProbe{}).Probe(context.Background(), kumaTarget(addr)); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestUptimeKumaProbe2FAIsNotSupported(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.Method == http.MethodPost:
			_, _ = w.Write([]byte("ok"))
		case r.URL.Query().Get("sid") == "":
			_, _ = w.Write([]byte(`0{"sid":"s1","pingInterval":25000}`))
		default:
			_, _ = w.Write([]byte(`430[{"ok":false,"tokenRequired":true}]`))
		}
	}))
	defer srv.Close()
	if _, err := (uptimeKumaProbe{}).Probe(context.Background(), kumaTarget(srv.URL)); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUptimeKumaProbeNotKuma(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("<!DOCTYPE html><html></html>"))
	}))
	defer srv.Close()
	if _, err := (uptimeKumaProbe{}).Probe(context.Background(), kumaTarget(srv.URL)); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestUptimeKumaProbeMeta(t *testing.T) {
	m := uptimeKumaProbe{}.Meta()
	if m.Product != "uptime-kuma" || !m.Auth.Required || !m.Auth.Accepts(AuthPassword) || m.Auth.Accepts(AuthBasic) {
		t.Fatalf("got %+v", m)
	}
}
