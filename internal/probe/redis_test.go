// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bufio"
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

func loadRedisFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// redis_7.4.11.bin is a real INFO server reply captured from a live
// redis:7.4 server, with the random run_id/build_id and this sandbox's own
// os: banner replaced by fixed placeholders — the parser only reads
// redis_version, so nothing real is lost.
func TestReadRESPBulkStringRealFixture(t *testing.T) {
	raw := loadRedisFixture(t, "redis_7.4.11.bin")
	info, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	version, ok := redisInfoField(info, "redis_version")
	if !ok {
		t.Fatalf("no redis_version field in %q", info)
	}
	if version != "7.4.11" {
		t.Fatalf("got %q, want 7.4.11", version)
	}
}

func TestReadRESPBulkStringErrorReply(t *testing.T) {
	raw := []byte("-ERR unknown command 'BOGUS'\r\n")
	_, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadRESPBulkStringNOAUTHIsErrAuth(t *testing.T) {
	raw := []byte("-NOAUTH Authentication required.\r\n")
	_, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestReadRESPBulkStringWrongType(t *testing.T) {
	raw := []byte(":42\r\n") // integer reply, not a bulk string
	_, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadRESPBulkStringNilReply(t *testing.T) {
	raw := []byte("$-1\r\n")
	_, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadRESPBulkStringTruncated(t *testing.T) {
	raw := []byte("$100\r\nnot actually 100 bytes")
	_, err := readRESPBulkString(bufio.NewReader(bytes.NewReader(raw)))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestRedisInfoFieldMissing(t *testing.T) {
	if _, ok := redisInfoField("# Server\r\nredis_mode:standalone\r\n", "redis_version"); ok {
		t.Fatal("expected no match")
	}
}

func TestRESPCommandEncoding(t *testing.T) {
	got := string(respCommand("AUTH", "secret"))
	want := "*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"
	if got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestRedisAuthSendsUsernameWhenSet(t *testing.T) {
	var sent bytes.Buffer
	reply := bufio.NewReader(bytes.NewReader([]byte("+OK\r\n")))
	err := redisAuth(&sent, reply, Credentials{Kind: AuthPassword, Username: "app", Password: "secret"})
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "*3\r\n$4\r\nAUTH\r\n$3\r\napp\r\n$6\r\nsecret\r\n"
	if sent.String() != want {
		t.Fatalf("got %q, want %q", sent.String(), want)
	}
}

func TestRedisAuthPasswordOnly(t *testing.T) {
	var sent bytes.Buffer
	reply := bufio.NewReader(bytes.NewReader([]byte("+OK\r\n")))
	if err := redisAuth(&sent, reply, Credentials{Kind: AuthPassword, Password: "secret"}); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	want := "*2\r\n$4\r\nAUTH\r\n$6\r\nsecret\r\n"
	if sent.String() != want {
		t.Fatalf("got %q, want %q", sent.String(), want)
	}
}

func TestRedisAuthWrongPasswordIsErrAuth(t *testing.T) {
	var sent bytes.Buffer
	reply := bufio.NewReader(bytes.NewReader([]byte("-WRONGPASS invalid username-password pair or user is disabled.\r\n")))
	err := redisAuth(&sent, reply, Credentials{Kind: AuthPassword, Password: "wrong"})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

// redisTestServer replays a scripted exchange: for each expected request it
// receives, it writes back the corresponding reply. Verifies the probe
// sends AUTH before INFO when credentials are set, not just that it can
// parse a reply handed to it directly.
func redisTestServer(t *testing.T, exchanges [][2][]byte) string {
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
		br := bufio.NewReader(conn)
		for _, ex := range exchanges {
			got := make([]byte, len(ex[0]))
			if _, err := io.ReadFull(br, got); err != nil {
				return
			}
			if !bytes.Equal(got, ex[0]) {
				t.Errorf("got request %q, want %q", got, ex[0])
			}
			if _, err := conn.Write(ex[1]); err != nil {
				return
			}
		}
	}()
	return ln.Addr().String()
}

func TestRedisProbeEndToEndNoAuth(t *testing.T) {
	raw := loadRedisFixture(t, "redis_7.4.11.bin")
	addr := redisTestServer(t, [][2][]byte{
		{respCommand("INFO", "server"), raw},
	})

	p := redisProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "redis", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.4.11" {
		t.Fatalf("got %+v", obs)
	}
}

func TestRedisProbeEndToEndWithAuth(t *testing.T) {
	raw := loadRedisFixture(t, "redis_7.4.11.bin")
	addr := redisTestServer(t, [][2][]byte{
		{respCommand("AUTH", "secret"), []byte("+OK\r\n")},
		{respCommand("INFO", "server"), raw},
	})

	p := redisProbe{}
	target := Target{
		ID: "x", Product: "redis", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Password: "secret"},
	}
	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.4.11" {
		t.Fatalf("got %+v", obs)
	}
}

func TestRedisProbeAuthRequiredButMissingIsErrAuth(t *testing.T) {
	addr := redisTestServer(t, [][2][]byte{
		{respCommand("INFO", "server"), []byte("-NOAUTH Authentication required.\r\n")},
	})

	p := redisProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "redis", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestRedisProbeUnreachable(t *testing.T) {
	p := redisProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "redis", Address: "127.0.0.1:1", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestRedisProbeMeta(t *testing.T) {
	m := redisProbe{}.Meta()
	if m.Product != "redis" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("redis auth is optional: most deployments have no requirepass")
	}
	if !m.Auth.Accepts(AuthPassword) {
		t.Fatal("expected AuthPassword to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "redis" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
