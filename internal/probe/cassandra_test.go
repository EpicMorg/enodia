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
)

// cqlReplayServer answers each frame the client sends with the next
// recorded response frame from fixture, in order — the fixtures are a live
// server's real replies, concatenated. got receives each request opcode.
func cqlReplayServer(t *testing.T, fixture string) (addr string, got <-chan byte) {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", fixture))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	ops := make(chan byte, 8)
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		replies := bytes.NewReader(raw)
		for replies.Len() > 0 {
			var h [9]byte
			if _, err := io.ReadFull(conn, h[:]); err != nil {
				return
			}
			ops <- h[4]
			n := int(h[5])<<24 | int(h[6])<<16 | int(h[7])<<8 | int(h[8])
			if _, err := io.ReadFull(conn, make([]byte, n)); err != nil {
				return
			}
			var rh [9]byte
			if _, err := io.ReadFull(replies, rh[:]); err != nil {
				return
			}
			rn := int(rh[5])<<24 | int(rh[6])<<16 | int(rh[7])<<8 | int(rh[8])
			frame := make([]byte, 9+rn)
			copy(frame, rh[:])
			if _, err := io.ReadFull(replies, frame[9:]); err != nil {
				return
			}
			if _, err := conn.Write(frame); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String(), ops
}

func TestCassandraProbeNoAuth(t *testing.T) {
	// cassandra:3.11: STARTUP -> READY, then the QUERY's Rows result.
	addr, ops := cqlReplayServer(t, "cassandra_3.11.19_noauth.bin")
	obs, err := cassandraProbe{}.Probe(context.Background(), target(addr, "cassandra"))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "3.11.19" {
		t.Fatalf("got %q", obs.Version)
	}
	if a, b := <-ops, <-ops; a != cqlOpStartup || b != cqlOpQuery {
		t.Fatalf("request opcodes 0x%02x 0x%02x", a, b)
	}
}

func TestCassandraProbePasswordAuth(t *testing.T) {
	// cassandra:5.0 with PasswordAuthenticator: AUTHENTICATE ->
	// AUTH_RESPONSE -> AUTH_SUCCESS -> QUERY.
	addr, ops := cqlReplayServer(t, "cassandra_5.0.9_auth.bin")
	tt := target(addr, "cassandra")
	tt.Creds = Credentials{Kind: AuthPassword, Username: "cassandra", Password: "cassandra"}
	obs, err := cassandraProbe{}.Probe(context.Background(), tt)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "5.0.9" {
		t.Fatalf("got %q", obs.Version)
	}
	if a, b, c := <-ops, <-ops, <-ops; a != cqlOpStartup || b != cqlOpAuthResponse || c != cqlOpQuery {
		t.Fatalf("request opcodes 0x%02x 0x%02x 0x%02x", a, b, c)
	}
}

func TestCassandraProbeBadPasswordIsErrAuth(t *testing.T) {
	addr, _ := cqlReplayServer(t, "cassandra_5.0.9_badauth.bin")
	tt := target(addr, "cassandra")
	tt.Creds = Credentials{Kind: AuthPassword, Username: "cassandra", Password: "wrong"}
	if _, err := (cassandraProbe{}).Probe(context.Background(), tt); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestCassandraProbeAuthRequiredWithoutCredsIsErrAuth(t *testing.T) {
	addr, _ := cqlReplayServer(t, "cassandra_5.0.9_badauth.bin") // its first reply is AUTHENTICATE
	if _, err := (cassandraProbe{}).Probe(context.Background(), target(addr, "cassandra")); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestCassandraProbeMeta(t *testing.T) {
	m := cassandraProbe{}.Meta()
	if m.Product != "cassandra" || m.Auth.Required || !m.Auth.Accepts(AuthPassword) || m.DefaultScheme != "" {
		t.Fatalf("got %+v", m)
	}
	if m.DefaultResolver != (ResolverRef{Type: "endoflife", ID: "apache-cassandra"}) {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
