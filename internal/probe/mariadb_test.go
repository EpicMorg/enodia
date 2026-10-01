// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// mariadb_10.11.19.bin is the same real handshake packet
// mysql_mariadb-masked.bin is (captured live from a real MariaDB 10.11
// server: "5.5.5-10.11.19-MariaDB-ubu2204") — kept as its own copy under
// this probe's own name per the one-fixture-per-probe convention, not
// because the bytes differ.
func mariadbFixtureListener(t *testing.T) net.Listener {
	t.Helper()
	raw := loadMySQLFixture(t, "mariadb_10.11.19.bin")
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(raw)
	}()
	return ln
}

func TestMariaDBProbeParsesRealFixture(t *testing.T) {
	ln := mariadbFixtureListener(t)
	defer ln.Close()

	p := mariadbProbe{}
	obs, err := p.Probe(context.Background(), Target{
		ID: "x", Product: "mariadb", Address: ln.Addr().String(), Timeout: 2 * time.Second,
	})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "10.11.19" {
		t.Fatalf("got version %q, want 10.11.19", obs.Version)
	}
	if obs.Extra["tag"] != "MariaDB-ubu2204" {
		t.Fatalf("got Extra %+v, want tag=MariaDB-ubu2204", obs.Extra)
	}
}

// A real MySQL 8.0 handshake carries no "5.5.5-" mask at all — mariadbProbe
// must reject it rather than misparse "8.0.46" as if it were the masked
// shape (D9; mysqlProbe already rejects the opposite direction).
func TestMariaDBProbeRejectsRealMySQL(t *testing.T) {
	raw := loadMySQLFixture(t, "mysql_8.0.46.bin")
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		_, _ = conn.Write(raw)
	}()

	p := mariadbProbe{}
	_, err = p.Probe(context.Background(), Target{
		ID: "x", Product: "mariadb", Address: ln.Addr().String(), Timeout: 2 * time.Second,
	})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestMariaDBProbeDefaultsPort(t *testing.T) {
	p := mariadbProbe{}
	_, err := p.Probe(context.Background(), Target{
		ID: "x", Product: "mariadb", Address: "127.0.0.1", Timeout: 50 * time.Millisecond,
	})
	// No listener on the default port in this sandbox — just confirm it
	// tried 3306 rather than failing on a missing port before that.
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable (connection refused/timeout on :3306)", err)
	}
}

func TestMariaDBProbeMeta(t *testing.T) {
	m := mariadbProbe{}.Meta()
	if m.Product != "mariadb" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty (raw TCP has no scheme)", m.DefaultScheme)
	}
	if m.Auth.Required {
		t.Fatal("the handshake needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "mariadb" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
