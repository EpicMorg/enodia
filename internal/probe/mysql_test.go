// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"errors"
	"io"
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

// MariaDB 11.0+ sends its version unmasked; mysqlProbe must still refuse it.
func TestReadMySQLHandshakeVersionRejectsUnmaskedMariaDB(t *testing.T) {
	for _, fixture := range []string{"mariadb_11.4.13.bin", "mariadb_12.3.3.bin"} {
		_, err := readMySQLHandshakeVersion(bytes.NewReader(loadMySQLFixture(t, fixture)))
		if !errors.Is(err, ErrNotSupported) {
			t.Fatalf("%s: got %v, want ErrNotSupported", fixture, err)
		}
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

func TestMySQLProbeDefaultsPort(t *testing.T) {
	// defaultPort itself is tested in tcp_test.go; this just confirms the
	// probe actually uses it with the right default.
	if got, want := defaultPort("db.example.com", mysqlDefaultPort), "db.example.com:3306"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestMySQLProbeEndToEnd(t *testing.T) {
	raw := loadMySQLFixture(t, "mysql_8.0.46.bin")
	addr := rawTCPTestServer(t, raw)

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

// mysqlGreetingServerCapturing writes greeting, then records the next packet
// the client sends (the HandshakeResponse) and replies with an Access-denied
// ERR, closing afterwards. The captured bytes are sent on the returned channel.
func mysqlGreetingServerCapturing(t *testing.T, greeting []byte) (string, <-chan []byte) {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })

	got := make(chan []byte, 1)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			got <- nil
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := conn.Write(greeting); err != nil {
			got <- nil
			return
		}
		header := make([]byte, 4)
		if _, err := io.ReadFull(conn, header); err != nil {
			got <- nil
			return
		}
		n := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
		payload := make([]byte, n)
		_, _ = io.ReadFull(conn, payload)
		got <- payload
		// 0xff ERR packet (Access denied), seq 2, so the probe's reply read
		// succeeds rather than hitting EOF.
		_, _ = conn.Write([]byte{0x09, 0x00, 0x00, 0x02, 0xff, 0x15, 0x04, 'd', 'e', 'n', 'i', 'e', 'd'})
	}()
	return ln.Addr().String(), got
}

func TestMySQLProbeAnswersGreeting(t *testing.T) {
	greeting := loadMySQLFixture(t, "mysql_8.0.46.bin")
	addr, got := mysqlGreetingServerCapturing(t, greeting)

	p := mysqlProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "mysql", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "8.0.46" {
		t.Fatalf("version %q, want 8.0.46", obs.Version)
	}

	resp := <-got
	if len(resp) == 0 {
		t.Fatal("probe sent no HandshakeResponse — the server would see an aborted pre-auth connection")
	}
	if !bytes.Contains(resp, []byte(mysqlProbeUser)) {
		t.Errorf("HandshakeResponse lacks the probe username %q: % x", mysqlProbeUser, resp)
	}
	if !bytes.Contains(resp, []byte("mysql_native_password")) {
		t.Errorf("HandshakeResponse lacks the auth plugin name: % x", resp)
	}
}
