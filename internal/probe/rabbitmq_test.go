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

func rabbitmqTarget(addr string) Target {
	tt := target(addr, "rabbitmq")
	tt.Creds = Credentials{Kind: AuthBasic, Username: "enodia", Password: "x"}
	tt.AllowInsecureTransport = true // httptest is plain HTTP
	return tt
}

// rabbitmq_4.3.6_overview.json is a real /api/overview reply from a live
// rabbitmq:4-management container, with its container hostname in
// node/cluster names replaced by "enodia-test".
func TestRabbitMQProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "rabbitmq_4.3.6_overview.json"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/overview" {
			t.Errorf("got path %q", r.URL.Path)
		}
		if u, p, ok := r.BasicAuth(); !ok || u != "enodia" || p != "x" {
			t.Errorf("Basic auth not sent")
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(raw)
	}))
	defer srv.Close()

	obs, err := rabbitmqProbe{}.Probe(context.Background(), rabbitmqTarget(srv.URL))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "4.3.6" || obs.Extra["productName"] != "RabbitMQ" || obs.Extra["erlangVersion"] != "27.3.4.18" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

// What the live container answered without credentials.
func TestRabbitMQProbeUnauthorized(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()
	_, err := rabbitmqProbe{}.Probe(context.Background(), rabbitmqTarget(srv.URL))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestRabbitMQProbeNotRabbitMQ(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"version":"1.0"}`))
	}))
	defer srv.Close()
	_, err := rabbitmqProbe{}.Probe(context.Background(), rabbitmqTarget(srv.URL))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestRabbitMQProbeMeta(t *testing.T) {
	m := rabbitmqProbe{}.Meta()
	if m.Product != "rabbitmq" || !m.Auth.Required || !m.Auth.Accepts(AuthBasic) || m.Auth.Accepts(AuthPassword) {
		t.Fatalf("got %+v", m)
	}
	if m.DefaultResolver != (ResolverRef{Type: "endoflife", ID: "rabbitmq"}) {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
