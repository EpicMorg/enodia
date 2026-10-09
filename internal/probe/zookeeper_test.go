// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"testing"
)

// zookeeperTestServer reads the 4-byte command first, as ZooKeeper does,
// then replies and closes — closing with the command unread would reset
// the connection under the client.
func zookeeperTestServer(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := io.ReadFull(conn, make([]byte, 4)); err != nil {
			return
		}
		_, _ = conn.Write(reply)
	}()
	return ln.Addr().String()
}

// zookeeper_3.9.6_srvr.bin is a live zookeeper:3.9 server's reply to
// "srvr", byte for byte.
func TestZookeeperProbeRealFixture(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("testdata", "zookeeper_3.9.6_srvr.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	obs, err := zookeeperProbe{}.Probe(context.Background(), target(zookeeperTestServer(t, raw), "zookeeper"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.9.6" || obs.Extra["mode"] != "standalone" || obs.Extra["git"] == "" {
		t.Fatalf("got %q %+v", obs.Version, obs.Extra)
	}
}

// What the same live server answered for a word outside the whitelist.
func TestZookeeperProbeNotWhitelisted(t *testing.T) {
	addr := zookeeperTestServer(t, []byte("srvr is not executed because it is not in the whitelist.\n"))
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
