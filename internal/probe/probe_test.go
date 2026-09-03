// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// serveFile stands up a throwaway server replying with a recorded response.
func serveFile(t *testing.T, path, fixture, ctype string, status int) *httptest.Server {
	t.Helper()
	body, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc(path, func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", ctype)
		w.WriteHeader(status)
		_, _ = w.Write(body)
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func target(addr, product string) Target {
	return Target{
		ID: "t1", Name: "test", Product: product, Address: addr,
		Timeout: 5 * time.Second, HTTP: &http.Client{Timeout: 5 * time.Second},
	}
}

func TestAtlassianProbes(t *testing.T) {
	cases := []struct {
		product, fixture, want, typeID string
	}{
		{"jira", "jira_10.3.2.xml", "10.3.2", "jira"},
		{"confluence", "confluence_9.2.1.xml", "9.2.1", "confluence"},
		{"bitbucket", "bitbucket_8.19.4.xml", "8.19.4", "stash"},
	}
	for _, c := range cases {
		t.Run(c.product, func(t *testing.T) {
			srv := serveFile(t, "/rest/applinks/1.0/manifest", c.fixture, "application/xml", 200)
			p, err := Get(c.product)
			if err != nil {
				t.Fatal(err)
			}
			obs, err := p.Probe(context.Background(), target(srv.URL, c.product))
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if obs.Version != c.want {
				t.Errorf("version = %q, want %q", obs.Version, c.want)
			}
			if obs.Extra["typeId"] != c.typeID {
				t.Errorf("typeId = %q, want %q", obs.Extra["typeId"], c.typeID)
			}
			if obs.Product != c.product {
				t.Errorf("product = %q, want %q", obs.Product, c.product)
			}
		})
	}
}

// Pointing a Confluence URL at a jira entry must be caught, not recorded as a
// Jira version. This is the entire reason product is declared explicitly.
func TestAtlassianWrongProduct(t *testing.T) {
	srv := serveFile(t, "/rest/applinks/1.0/manifest", "confluence_9.2.1.xml", "application/xml", 200)
	p, _ := Get("jira")
	_, err := p.Probe(context.Background(), target(srv.URL, "jira"))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("err = %v, want ErrNotSupported", err)
	}
	if !strings.Contains(err.Error(), "confluence") {
		t.Errorf("error should name what was actually found: %v", err)
	}
}

func TestErrorClassification(t *testing.T) {
	cases := []struct {
		name, path string
		status     int
		wantKind   string
		retryable  bool
	}{
		{"auth", "/rest/applinks/1.0/manifest", 401, "auth", false},
		{"forbidden", "/rest/applinks/1.0/manifest", 403, "auth", false},
		{"missing endpoint", "/rest/applinks/1.0/manifest", 404, "not_supported", false},
		{"server error", "/rest/applinks/1.0/manifest", 503, "unreachable", true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := serveFile(t, c.path, "jira_10.3.2.xml", "application/xml", c.status)
			p, _ := Get("jira")
			_, err := p.Probe(context.Background(), target(srv.URL, "jira"))
			if err == nil {
				t.Fatal("expected an error")
			}
			if got := Kind(err); got != c.wantKind {
				t.Errorf("kind = %q, want %q (%v)", got, c.wantKind, err)
			}
			if Retryable(err) != c.retryable {
				t.Errorf("retryable = %v, want %v", Retryable(err), c.retryable)
			}
		})
	}
}

func TestUnparseableIsOurBug(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/applinks/1.0/manifest", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`<applinks-manifest><typeId>jira</typeId></applinks-manifest>`))
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	p, _ := Get("jira")
	_, err := p.Probe(context.Background(), target(srv.URL, "jira"))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("a manifest without <version> must be ErrUnparseable, got %v", err)
	}
}

func TestGenericProbe(t *testing.T) {
	cases := []struct {
		name, fixture, ctype string
		spec                 ParserSpec
		want                 string
	}{
		{"json dotted", "generic_nextcloud_30.0.2.json", "application/json",
			ParserSpec{Type: "json", Key: "versionstring"}, "30.0.2"},
		{"xml root attribute", "generic_teamcity_2025.03.1.xml", "application/xml",
			ParserSpec{Type: "xml", Key: "@version", CleanRegex: `^([0-9.]+)`}, "2025.03.1"},
		{"plaintext", "generic_sonarqube_10.7.txt", "text/plain",
			ParserSpec{Type: "plaintext"}, "10.7.0.96327"},
		{"regex", "generic_sonarqube_10.7.txt", "text/plain",
			ParserSpec{Type: "regex", Regex: `(\d+\.\d+)`}, "10.7"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			srv := serveFile(t, "/api/version", c.fixture, c.ctype, 200)
			tg := target(srv.URL, "generic")
			tg.Path = "/api/version"
			tg.Parser = &c.spec
			p, _ := Get("generic")
			obs, err := p.Probe(context.Background(), tg)
			if err != nil {
				t.Fatalf("probe: %v", err)
			}
			if obs.Version != c.want {
				t.Errorf("version = %q, want %q", obs.Version, c.want)
			}
		})
	}
}

// A version header served alongside 403 is the Jenkins pattern: the version is
// readable without credentials.
func TestGenericHeaderOn403(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("X-Jenkins", "2.492.1")
		w.WriteHeader(403)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	tg := target(srv.URL, "generic")
	tg.Path = "/"
	tg.Parser = &ParserSpec{Type: "header", Key: "X-Jenkins"}
	p, _ := Get("generic")
	obs, err := p.Probe(context.Background(), tg)
	if err != nil {
		t.Fatalf("probe: %v", err)
	}
	if obs.Version != "2.492.1" {
		t.Errorf("version = %q, want 2.492.1", obs.Version)
	}
}

// Credentials must never travel over plain HTTP without explicit consent.
func TestRefusesCredentialsOverPlainHTTP(t *testing.T) {
	srv := serveFile(t, "/rest/applinks/1.0/manifest", "jira_10.3.2.xml", "application/xml", 200)
	tg := target(srv.URL, "jira") // httptest is plain http
	tg.Creds = Credentials{Kind: AuthBearer, Value: "secret-token"}

	p, _ := Get("jira")
	_, err := p.Probe(context.Background(), tg)
	if !errors.Is(err, ErrInsecure) {
		t.Fatalf("err = %v, want ErrInsecure", err)
	}
	if strings.Contains(err.Error(), "secret-token") {
		t.Fatal("the error message leaked the credential")
	}

	tg.AllowInsecureTransport = true
	if _, err := p.Probe(context.Background(), tg); err != nil {
		t.Fatalf("with explicit consent the probe should proceed: %v", err)
	}
}

func TestCredentialsNeverFormat(t *testing.T) {
	c := Credentials{Kind: AuthBearer, Value: "hunter2", Password: "hunter2"}
	for _, s := range []string{
		strings.TrimSpace(strings.Join([]string{c.String(), c.GoString()}, " ")),
	} {
		if strings.Contains(s, "hunter2") {
			t.Fatalf("credential leaked through formatting: %s", s)
		}
	}
}

func TestRegistryHasNoDuplicates(t *testing.T) {
	seen := map[string]bool{}
	for _, p := range All() {
		m := p.Meta()
		if seen[m.Product] {
			t.Errorf("duplicate product %q", m.Product)
		}
		seen[m.Product] = true
		if m.Product == "" {
			t.Error("a probe declares an empty product id")
		}
	}
	if _, err := Get("definitely-not-a-product"); err == nil {
		t.Error("unknown products must be rejected")
	}
}

func TestContextCancellation(t *testing.T) {
	mux := http.NewServeMux()
	mux.HandleFunc("/rest/applinks/1.0/manifest", func(_ http.ResponseWriter, _ *http.Request) {
		time.Sleep(2 * time.Second)
	})
	srv := httptest.NewServer(mux)
	defer srv.Close()

	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()

	p, _ := Get("jira")
	start := time.Now()
	if _, err := p.Probe(ctx, target(srv.URL, "jira")); err == nil {
		t.Fatal("expected cancellation")
	}
	if d := time.Since(start); d > time.Second {
		t.Errorf("cancellation took %s; context is not being honoured", d)
	}
}
