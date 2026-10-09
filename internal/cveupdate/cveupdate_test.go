// SPDX-License-Identifier: AGPL-3.0-or-later

package cveupdate

import (
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

func touch(t *testing.T, path string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
}

func dests(items []Item, source string) []string {
	var out []string
	for _, it := range items {
		if it.Source == source {
			out = append(out, filepath.Base(it.Dest))
		}
	}
	return out
}

func TestPlanNVDYears(t *testing.T) {
	dir := t.TempDir()
	for y := 2002; y <= 2026; y++ {
		if y != 2010 {
			touch(t, filepath.Join(dir, "nvdcve-2.0-"+strconv.Itoa(y)+".json.gz"))
		}
	}
	now := time.Date(2026, 10, 9, 0, 0, 0, 0, time.UTC)

	items, errs := Plan(Paths{NVD: dir}, Wants{}, now, false)
	if len(errs) != 0 {
		t.Fatal(errs)
	}
	want := []string{"nvdcve-2.0-2010.json.gz", "nvdcve-2.0-2025.json.gz", "nvdcve-2.0-2026.json.gz"}
	if got := dests(items, "nvd"); !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
	if items, _ := Plan(Paths{NVD: dir}, Wants{}, now, true); len(items) != 25 {
		t.Errorf("--all-years: got %d items, want 25", len(items))
	}
}

func TestPlanOVALAlpinePostgreSQL(t *testing.T) {
	root := t.TempDir()
	oval, alpine, pg := filepath.Join(root, "oval"), filepath.Join(root, "alpine"), filepath.Join(root, "postgresql")
	touch(t, filepath.Join(oval, "com.ubuntu.jammy.usn.oval.xml")) // an uncompressed copy still names its release
	touch(t, filepath.Join(oval, "redos-7.3.xml"))
	touch(t, filepath.Join(oval, "notes.txt"))
	touch(t, filepath.Join(alpine, "v3.20-main.json"))
	touch(t, filepath.Join(pg, "13.html"))

	items, errs := Plan(Paths{OVAL: oval, Alpine: alpine, PostgreSQL: pg}, Wants{
		OVAL:       []string{"ubuntu:noble", "rocky-linux:9", "rhel:9", "astra:1.8", "debian:13"},
		Alpine:     []string{"v3.22", "3.22"},
		PostgreSQL: []string{"9.6", "17"},
	}, time.Now(), false)

	if len(errs) != 2 || !strings.Contains(errs[0].Error()+errs[1].Error(), "debian:13") {
		t.Errorf("want errors for debian:13 and 3.22, got %v", errs)
	}
	wantOVAL := []string{"oval-definitions-alse-1.8.xml", "rhel-9.oval.xml.bz2", "redos-7.3.xml", "com.ubuntu.jammy.usn.oval.xml.bz2", "com.ubuntu.noble.usn.oval.xml.bz2"}
	if got := dests(items, "oval"); !sameSet(got, wantOVAL) {
		t.Errorf("oval: got %v, want %v", got, wantOVAL)
	}
	for _, it := range items {
		if strings.Contains(it.Dest, "jammy") && (len(it.replaces) != 1 || filepath.Base(it.replaces[0]) != "com.ubuntu.jammy.usn.oval.xml") {
			t.Errorf("jammy's .bz2 must replace the uncompressed copy, replaces %v", it.replaces)
		}
	}
	wantAlpine := []string{"v3.20-main.json", "v3.20-community.json", "v3.22-main.json", "v3.22-community.json"}
	if got := dests(items, "alpine"); !sameSet(got, wantAlpine) {
		t.Errorf("alpine: got %v, want %v", got, wantAlpine)
	}
	wantPG := []string{"security.html", "13.html", "17.html", "9.6.html"}
	if got := dests(items, "postgresql"); !sameSet(got, wantPG) {
		t.Errorf("postgresql: got %v, want %v", got, wantPG)
	}
	for _, it := range items {
		if it.Source == "postgresql" && filepath.Base(it.Dest) == "9.6.html" && it.URL != pgURL+"9.6/" {
			t.Errorf("9.6 page URL %s", it.URL)
		}
	}
}

func TestPlanRejectsUnfetchableShapes(t *testing.T) {
	root := t.TempDir()
	nvdFile := filepath.Join(root, "nvd.json.gz")
	touch(t, nvdFile)
	_, errs := Plan(Paths{
		BDU:    filepath.Join(root, "vulxml.xml"),
		NVD:    nvdFile,
		Debian: filepath.Join(root, "debian.json.gz"),
		OVAL:   filepath.Join(root, "rhel-9.oval.xml"),
	}, Wants{}, time.Now(), false)
	if len(errs) != 4 {
		t.Errorf("got %d errors, want 4: %v", len(errs), errs)
	}
	items, _ := Plan(Paths{PostgreSQL: filepath.Join(root, "pg.html")}, Wants{PostgreSQL: []string{"13"}}, time.Now(), false)
	if len(items) != 1 || items[0].URL != pgURL {
		t.Errorf("a PostgreSQL file path gets the main page only, got %+v", items)
	}
}

func TestWantsFromInventory(t *testing.T) {
	w := WantsFromInventory([]probe.Observation{
		{Product: "ubuntu", Version: "24.04", Extra: map[string]string{"codename": "noble"}},
		{Product: "linuxmint", Version: "22.1", Extra: map[string]string{"codename": "noble"}},
		{Product: "rocky-linux", Version: "9.4"},
		{Product: "astra-linux", Version: "1.8.1"},
		{Product: "alpine-linux", Version: "3.22.1"},
		{Product: "postgresql", Version: "9.6.24"},
		{Product: "postgresql", Version: "17.2"},
		{Product: "nginx", Version: "1.30.5"},
	})
	if want := []string{"ubuntu:noble", "ubuntu:noble", "rocky-linux:9", "astra-linux:1.8"}; !slices.Equal(w.OVAL, want) {
		t.Errorf("OVAL %v, want %v", w.OVAL, want)
	}
	if !slices.Equal(w.Alpine, []string{"v3.22"}) || !slices.Equal(w.PostgreSQL, []string{"9.6", "17"}) {
		t.Errorf("Alpine %v, PostgreSQL %v", w.Alpine, w.PostgreSQL)
	}
}

// server serves body with Last-Modified lm (none if zero), answers
// If-Modified-Since, and fails the first `fail` requests with 503.
func server(t *testing.T, body string, lm time.Time, fail int32) (*httptest.Server, *atomic.Int32) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if hits.Add(1) <= fail {
			w.WriteHeader(http.StatusServiceUnavailable)
			return
		}
		if !lm.IsZero() {
			if ims, err := http.ParseTime(r.Header.Get("If-Modified-Since")); err == nil && !lm.After(ims) {
				w.WriteHeader(http.StatusNotModified)
				return
			}
			w.Header().Set("Last-Modified", lm.UTC().Format(http.TimeFormat))
		}
		_, _ = w.Write([]byte(body))
	}))
	t.Cleanup(srv.Close)
	return srv, &hits
}

func testClient() *Client {
	return &Client{HTTP: http.DefaultClient, UserAgent: "enodia-test", Attempts: 3, Backoff: time.Millisecond}
}

func okCheck(path string) error {
	b, err := os.ReadFile(path)
	if err == nil && !strings.HasPrefix(string(b), "ok") {
		err = errors.New("not ok")
	}
	return err
}

func TestFetchNewThenSame(t *testing.T) {
	lm := time.Date(2026, 10, 1, 12, 0, 0, 0, time.UTC)
	srv, hits := server(t, "ok v1", lm, 1)
	dest := filepath.Join(t.TempDir(), "sub", "data.json")
	it := Item{Source: "x", URL: srv.URL, Dest: dest, check: okCheck}

	if r := testClient().Fetch(context.Background(), it); r.Status != New {
		t.Fatalf("first fetch: %+v", r)
	}
	if hits.Load() != 2 {
		t.Errorf("want one retry after the 503, got %d requests", hits.Load())
	}
	if st, _ := os.Stat(dest); !st.ModTime().Equal(lm) {
		t.Errorf("mtime %v, want Last-Modified %v", st.ModTime(), lm)
	}
	stale := filepath.Join(filepath.Dir(dest), "data-old.json")
	touch(t, stale)
	it.replaces = []string{stale}
	if r := testClient().Fetch(context.Background(), it); r.Status != Same {
		t.Fatalf("second fetch: %+v", r)
	}
	if _, err := os.Stat(stale); !os.IsNotExist(err) {
		t.Errorf("the replaced copy is still there: %v", err)
	}
	if _, err := os.Stat(filepath.Join(filepath.Dir(dest), tmpDirName)); !os.IsNotExist(err) {
		t.Errorf("temp dir left behind: %v", err)
	}
}

func TestFetchBrokenDownloadKeepsOldFile(t *testing.T) {
	srv, _ := server(t, "<html>maintenance</html>", time.Now(), 0)
	dest := filepath.Join(t.TempDir(), "data.json")
	if err := os.WriteFile(dest, []byte("ok old"), 0o644); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(dest, old, old)

	r := testClient().Fetch(context.Background(), Item{URL: srv.URL, Dest: dest, check: okCheck})
	if r.Status != Failed {
		t.Fatalf("got %+v, want Failed", r)
	}
	if b, _ := os.ReadFile(dest); string(b) != "ok old" {
		t.Errorf("old file replaced: %q", b)
	}
}

func TestFetchWithoutLastModifiedComparesContent(t *testing.T) {
	srv, _ := server(t, "ok same", time.Time{}, 0)
	dest := filepath.Join(t.TempDir(), "page.html")
	if err := os.WriteFile(dest, []byte("ok same"), 0o644); err != nil {
		t.Fatal(err)
	}
	if r := testClient().Fetch(context.Background(), Item{URL: srv.URL, Dest: dest, check: okCheck}); r.Status != Same {
		t.Errorf("got %+v, want Same", r)
	}
}

func TestFetchNotFoundIsNotRetried(t *testing.T) {
	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		http.NotFound(w, nil)
	}))
	defer srv.Close()
	r := testClient().Fetch(context.Background(), Item{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "f")})
	if r.Status != Failed || hits.Load() != 1 {
		t.Errorf("got %+v after %d requests, want Failed after 1", r, hits.Load())
	}
}

func TestNewClientTLS(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte("ok tls"))
	}))
	defer srv.Close()
	dir := t.TempDir()
	caDir := filepath.Join(dir, "certs")
	pemFile := filepath.Join(caDir, "test-ca.pem")
	touch(t, pemFile)
	if err := os.WriteFile(pemFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0o644); err != nil {
		t.Fatal(err)
	}
	// Glued by cat without a newline between the two certificates.
	pemBlock := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})
	gluedFile := filepath.Join(dir, "glued.pem")
	if err := os.WriteFile(gluedFile, append(bytes.TrimSpace(pemBlock), pemBlock...), 0o644); err != nil {
		t.Fatal(err)
	}
	derFile := filepath.Join(dir, "test-ca.cer")
	if err := os.WriteFile(derFile, srv.Certificate().Raw, 0o644); err != nil {
		t.Fatal(err)
	}

	fetch := func(opts TLSOptions) Status {
		t.Helper()
		c, err := NewClient(opts, "enodia-test")
		if err != nil {
			t.Fatalf("NewClient(%+v): %v", opts, err)
		}
		c.Attempts, c.Backoff = 1, time.Millisecond
		return c.Fetch(context.Background(), Item{URL: srv.URL, Dest: filepath.Join(t.TempDir(), "f"), check: okCheck}).Status
	}
	for name, tc := range map[string]struct {
		opts TLSOptions
		want Status
	}{
		"system roots only": {TLSOptions{}, Failed},
		"ca_file PEM":       {TLSOptions{CAFile: pemFile}, New},
		"ca_file DER":       {TLSOptions{CAFile: derFile}, New},
		"ca_file glued":     {TLSOptions{CAFile: gluedFile}, New},
		"ca_dir":            {TLSOptions{CADir: caDir}, New},
		"tls_skip_verify":   {TLSOptions{SkipVerify: true}, New},
	} {
		if got := fetch(tc.opts); got != tc.want {
			t.Errorf("%s: got %s, want %s", name, got, tc.want)
		}
	}
	if _, err := NewClient(TLSOptions{CAFile: filepath.Join(dir, "missing.pem")}, "x"); err == nil {
		t.Error("a missing ca_file must be an error")
	}
}

func sameSet(a, b []string) bool {
	a, b = slices.Clone(a), slices.Clone(b)
	slices.Sort(a)
	slices.Sort(b)
	return slices.Equal(a, b)
}
