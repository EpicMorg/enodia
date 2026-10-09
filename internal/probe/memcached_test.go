// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// memcached_1.6.45.bin is the real reply of a live memcached:1.6 server to
// "version\r\n", byte for byte.
func TestMemcachedProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "memcached_1.6.45.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	addr := rawTCPTestServer(t, raw)

	obs, err := memcachedProbe{}.Probe(context.Background(), target(addr, "memcached"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.6.45" || obs.Endpoint != addr {
		t.Fatalf("got version %q endpoint %q", obs.Version, obs.Endpoint)
	}
}

func TestParseMemcachedVersion(t *testing.T) {
	for _, tc := range []struct {
		line, want string
		err        error
	}{
		{"VERSION 1.6.45\r\n", "1.6.45", nil},
		{"VERSION 1.4.15\r\n", "1.4.15", nil},
		{"ERROR\r\n", "", ErrNotSupported},
		{"+OK\r\n", "", ErrUnparseable},
	} {
		got, err := parseMemcachedVersion(tc.line)
		if tc.err != nil {
			if !errors.Is(err, tc.err) {
				t.Errorf("%q: got %v, want %v", tc.line, err, tc.err)
			}
			continue
		}
		if err != nil || got != tc.want {
			t.Errorf("%q: got %q, %v; want %q", tc.line, got, err, tc.want)
		}
	}
}

func TestMemcachedProbeMeta(t *testing.T) {
	m := memcachedProbe{}.Meta()
	if m.Product != "memcached" || m.Auth.Required || m.DefaultResolver != (ResolverRef{Type: "endoflife", ID: "memcached"}) {
		t.Fatalf("got %+v", m)
	}
	if m.DefaultScheme != "" {
		t.Fatal("raw TCP has no URL scheme")
	}
}
