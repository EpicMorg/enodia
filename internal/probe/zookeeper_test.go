// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// zookeeper_3.9.6_srvr.bin is a live zookeeper:3.9 server's reply to
// "srvr", byte for byte.
func TestZookeeperProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "zookeeper_3.9.6_srvr.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := zookeeperProbe{}.Probe(context.Background(), target(rawTCPTestServer(t, raw), "zookeeper"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.9.6" || obs.Extra["mode"] != "standalone" || obs.Extra["git"] == "" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

// What the same live server answered for a word outside the whitelist.
func TestZookeeperProbeNotWhitelisted(t *testing.T) {
	addr := rawTCPTestServer(t, []byte("srvr is not executed because it is not in the whitelist.\n"))
	if _, err := (zookeeperProbe{}).Probe(context.Background(), target(addr, "zookeeper")); !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestZookeeperProbeMeta(t *testing.T) {
	m := zookeeperProbe{}.Meta()
	if m.Product != "zookeeper" || m.Auth.Required || m.DefaultResolver != (ResolverRef{Type: "endoflife", ID: "zookeeper"}) {
		t.Fatalf("got %+v", m)
	}
}
