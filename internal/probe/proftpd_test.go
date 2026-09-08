// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadProFTPDFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// proftpd_default_greeting.txt is a real FTP greeting captured from a live
// production ProFTPD host (hostname/IP scrubbed) with no ServerIdent
// directive configured — confirmed by reading src/session.c to be
// ProFTPD's own compiled-in default, not a hardening step: it carries no
// version at all.
func TestProFTPDProbeDefaultGreetingIsNotSupported(t *testing.T) {
	raw := loadProFTPDFixture(t, "proftpd_default_greeting.txt")
	addr := rawTCPTestServer(t, raw)

	p := proftpdProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "proftpd", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

// proftpd_1.3.9c_greeting.txt is a real greeting captured from the same
// instantlinux/proftpd container after adding
// `ServerIdent on "ProFTPD %{version} ready at %L"` to its config and
// restarting — confirmed live that ProFTPD's own %{version} substitution
// produces exactly this text (IP scrubbed).
func TestProFTPDProbeParsesCustomServerIdent(t *testing.T) {
	raw := loadProFTPDFixture(t, "proftpd_1.3.9c_greeting.txt")
	addr := rawTCPTestServer(t, raw)

	p := proftpdProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "proftpd", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "1.3.9c" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestProFTPDProbeWrongProduct(t *testing.T) {
	addr := rawTCPTestServer(t, []byte("220 Welcome to pure-ftpd\r\n"))

	p := proftpdProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "proftpd", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestReadFTPGreetingSkipsContinuationLines(t *testing.T) {
	raw := "220-Welcome to the server\r\n220-Authorized access only\r\n220 ProFTPD Server (example) [192.0.2.1]\r\n"
	line, err := readFTPGreeting(bufio.NewReader(bytes.NewReader([]byte(raw))))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if line != "220 ProFTPD Server (example) [192.0.2.1]" {
		t.Fatalf("got %q", line)
	}
}

func TestProFTPDProbeUnreachable(t *testing.T) {
	p := proftpdProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "proftpd", Address: "127.0.0.1:1", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestProFTPDProbeMeta(t *testing.T) {
	m := proftpdProbe{}.Meta()
	if m.Product != "proftpd" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty", m.DefaultScheme)
	}
	if m.Auth.Required {
		t.Fatal("the greeting needs no credentials")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "proftpd" {
		t.Fatalf("got resolver %+v, want endoflife/proftpd", m.DefaultResolver)
	}
}
