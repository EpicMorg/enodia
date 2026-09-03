// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadMySQLFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// mysql_8.0.46.bin is a real handshake packet captured from a live MySQL
// 8.0 server (docker.io/library/mysql:8.0), with everything after the
// version string's NUL terminator zeroed — the parser never reads past it.
func TestReadMySQLHandshakeVersionRealFixture(t *testing.T) {
	raw := loadMySQLFixture(t, "mysql_8.0.46.bin")
	version, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "8.0.46" {
		t.Fatalf("got %q, want 8.0.46", version)
	}
}

// mysql_mariadb-masked.bin is a real handshake captured from a live
// MariaDB 10.11 server, still using the "5.5.5-" masking prefix today —
// confirmed live, not assumed from older documentation.
func TestReadMySQLHandshakeVersionRejectsMariaDB(t *testing.T) {
	raw := loadMySQLFixture(t, "mysql_mariadb-masked.bin")
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestReadMySQLHandshakeVersionTruncatedHeader(t *testing.T) {
	_, err := readMySQLHandshakeVersion(bytes.NewReader([]byte{0x01, 0x00}))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestReadMySQLHandshakeVersionTruncatedPayload(t *testing.T) {
	// Header claims 74 bytes but only a handful follow.
	raw := []byte{0x4a, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0'}
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestReadMySQLHandshakeVersionImplausibleLength(t *testing.T) {
	raw := []byte{0xff, 0xff, 0xff, 0x00} // length far beyond maxMySQLHandshake
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadMySQLHandshakeVersionWrongProtocolVersion(t *testing.T) {
	raw := []byte{0x03, 0x00, 0x00, 0x00, 0x09, '8', '.'} // protocol version 9, not 10
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestReadMySQLHandshakeVersionNoTerminator(t *testing.T) {
	raw := []byte{0x03, 0x00, 0x00, 0x00, 0x0a, '8', '.', '0'} // no NUL anywhere
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadMySQLHandshakeVersionERRPacket(t *testing.T) {
	// 0xff marker, error code 1040 (ER_CON_COUNT_ERROR), little-endian.
	raw := []byte{0x05, 0x00, 0x00, 0x00, 0xff, 0x10, 0x04, 'x'}
	_, err := readMySQLHandshakeVersion(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestMySQLAddressDefaultsPort(t *testing.T) {
	if got, want := mysqlAddress("db.example.com"), "db.example.com:3306"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMySQLAddressKeepsExplicitPort(t *testing.T) {
	if got, want := mysqlAddress("db.example.com:3307"), "db.example.com:3307"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMySQLAddressStripsTCPScheme(t *testing.T) {
	if got, want := mysqlAddress("tcp://db.example.com:3306"), "db.example.com:3306"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// mysqlTestServer replays raw over one accepted connection.
func mysqlTestServer(t *testing.T, raw []byte) string {
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
		_, _ = conn.Write(raw)
	}()
	return ln.Addr().String()
}

func TestMySQLProbeEndToEnd(t *testing.T) {
	raw := loadMySQLFixture(t, "mysql_8.0.46.bin")
	addr := mysqlTestServer(t, raw)

	p := mysqlProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "mysql", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.0.46" {
		t.Fatalf("got %+v", obs)
	}
	if obs.Endpoint != addr {
		t.Fatalf("got endpoint %q, want %q", obs.Endpoint, addr)
	}
}

func TestMySQLProbeUnreachable(t *testing.T) {
	p := mysqlProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "mysql", Address: "127.0.0.1:1", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestMySQLProbeRespectsContextCancellation(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		defer conn.Close()
		time.Sleep(2 * time.Second) // never sends a handshake
	}()

	ctx, cancel := context.WithCancel(context.Background())
	p := mysqlProbe{}

	done := make(chan error, 1)
	go func() {
		_, err := p.Probe(ctx, Target{ID: "x", Product: "mysql", Address: ln.Addr().String(), Timeout: 30 * time.Second})
		done <- err
	}()

	<-accepted
	cancel()

	select {
	case err := <-done:
		if !errors.Is(err, ErrUnreachable) {
			t.Fatalf("got %v, want ErrUnreachable (from context cancellation)", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Probe did not return promptly after context cancellation")
	}
}

func TestMySQLProbeMeta(t *testing.T) {
	m := mysqlProbe{}.Meta()
	if m.Product != "mysql" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty (raw TCP has no scheme)", m.DefaultScheme)
	}
	if m.Auth.Required {
		t.Fatal("the handshake needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "mysql" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
