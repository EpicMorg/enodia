// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadSSHFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// ssh_openssh.bin is a real identification line captured from a live
// linuxserver/openssh-server container.
func TestReadSSHIdentificationRealFixtureBare(t *testing.T) {
	raw := loadSSHFixture(t, "ssh_openssh.bin")
	proto, software, err := readSSHIdentification(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "2.0" {
		t.Fatalf("got proto %q, want 2.0", proto)
	}
	if software != "OpenSSH_10.3" {
		t.Fatalf("got software %q, want OpenSSH_10.3", software)
	}
}

// ssh_openssh_ubuntu.bin is a real identification line captured from a live
// Ubuntu 24.04 sshd, which appends a "comments" field (RFC 4253 §4.2) the
// bare fixture above never exercises: a distro suffix containing its own
// hyphen, which a naive "split on last/only hyphen" parser would mishandle.
func TestReadSSHIdentificationRealFixtureWithComment(t *testing.T) {
	raw := loadSSHFixture(t, "ssh_openssh_ubuntu.bin")
	proto, software, err := readSSHIdentification(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "2.0" {
		t.Fatalf("got proto %q, want 2.0", proto)
	}
	if software != "OpenSSH_9.6p1" {
		t.Fatalf("got software %q, want OpenSSH_9.6p1 (comment must be discarded)", software)
	}
}

func TestReadSSHIdentificationSkipsPrecedingBannerLines(t *testing.T) {
	// RFC 4253 §4.2 explicitly allows this: lines before the id string that
	// must not themselves start with "SSH-".
	raw := []byte("Welcome to ACME Corp gateway\r\nUnauthorized access is prohibited\r\nSSH-2.0-dropbear_2022.83\r\n")
	proto, software, err := readSSHIdentification(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "2.0" || software != "dropbear_2022.83" {
		t.Fatalf("got proto=%q software=%q", proto, software)
	}
}

func TestReadSSHIdentificationBareLFIsAccepted(t *testing.T) {
	// Some lenient/embedded implementations send only LF, no CR.
	raw := []byte("SSH-2.0-OpenSSH_9.1\n")
	proto, software, err := readSSHIdentification(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if proto != "2.0" || software != "OpenSSH_9.1" {
		t.Fatalf("got proto=%q software=%q", proto, software)
	}
}

func TestReadSSHIdentificationGivesUpAfterMaxLines(t *testing.T) {
	var buf bytes.Buffer
	for i := 0; i < maxSSHLines+5; i++ {
		buf.WriteString("just some banner text\r\n")
	}
	_, _, err := readSSHIdentification(bytes.NewReader(buf.Bytes()))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestReadSSHIdentificationEOFBeforeAnyLine(t *testing.T) {
	_, _, err := readSSHIdentification(bytes.NewReader(nil))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestParseSSHIdentificationMissingPrefix(t *testing.T) {
	_, _, err := parseSSHIdentification("not-an-ssh-line")
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestParseSSHIdentificationMissingSeparator(t *testing.T) {
	_, _, err := parseSSHIdentification("SSH-2.0")
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestSSHProbeEndToEnd(t *testing.T) {
	raw := loadSSHFixture(t, "ssh_openssh_ubuntu.bin")
	addr := rawTCPTestServer(t, raw)

	p := sshProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "ssh", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "OpenSSH_9.6p1" {
		t.Fatalf("got %+v", obs)
	}
	if obs.Extra["protocol"] != "2.0" {
		t.Fatalf("got extra %+v", obs.Extra)
	}
}

func TestSSHProbeUnreachable(t *testing.T) {
	p := sshProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "ssh", Address: "127.0.0.1:1", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestSSHProbeMeta(t *testing.T) {
	m := sshProbe{}.Meta()
	if m.Product != "ssh" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.DefaultScheme != "" {
		t.Fatalf("got DefaultScheme %q, want empty", m.DefaultScheme)
	}
	if m.Auth.Required {
		t.Fatal("the banner needs no credentials")
	}
}
