// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strings"
	"time"
)

// sshProbe reads the identification string every SSH server sends
// unprompted the instant a client connects (RFC 4253 §4.2) — no
// authentication, no key exchange, nothing but a TCP connection. Not tied
// to one vendor: OpenSSH, Dropbear and anything else speaking the SSH
// transport protocol all identify themselves the same way, so the product
// is generic "ssh" rather than one probe per implementation.
type sshProbe struct{}

func (sshProbe) Meta() Meta {
	return Meta{
		Product: "ssh",
		Summary: "SSH banner (any implementation)",
		Auth:    AuthSpec{Required: false},
		// No DefaultResolver: "ssh" isn't one product with one lifecycle
		// calendar — OpenSSH and Dropbear each have their own, and Meta is
		// static per probe (D-something: it must not depend on what the
		// response turns out to say).
	}
}

const (
	sshDefaultPort = "22"
	maxSSHLines    = 20   // RFC 4253 allows banner lines before the id string
	maxSSHLineLen  = 1024 // real id strings are under 255 bytes; this is generous
)

func (sshProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, sshDefaultPort)

	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	proto, software, err := readSSHIdentification(conn)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	obs.Version = software
	obs.Endpoint = addr
	obs.Extra = map[string]string{"protocol": proto}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// readSSHIdentification reads lines until it finds the one starting with
// "SSH-", per RFC 4253 §4.2: "The server MAY send other lines of data
// before sending the version string. ... Such lines MUST NOT begin with
// 'SSH-'." Everything up to maxSSHLines is tried before giving up, so a
// server that never sends one fails rather than blocking forever once its
// deadline passes.
//
// Verified against two live servers rather than assumed from the RFC alone:
// a bare "SSH-2.0-OpenSSH_10.3" (testdata/ssh_openssh.bin) and Ubuntu's
// packaging, which appends a comment field the RFC allows but the bare form
// doesn't exercise: "SSH-2.0-OpenSSH_9.6p1 Ubuntu-3ubuntu13.18"
// (testdata/ssh_openssh_ubuntu.bin).
func readSSHIdentification(r io.Reader) (protoVersion, softwareVersion string, err error) {
	br := bufio.NewReaderSize(r, maxSSHLineLen)
	for i := 0; i < maxSSHLines; i++ {
		line, err := br.ReadString('\n')
		if err != nil {
			return "", "", fmt.Errorf("%w: reading identification line: %w", ErrUnreachable, err)
		}
		line = strings.TrimRight(line, "\r\n")
		if !strings.HasPrefix(line, "SSH-") {
			continue
		}
		return parseSSHIdentification(line)
	}
	return "", "", fmt.Errorf("%w: no line starting with %q in the first %d lines", ErrUnparseable, "SSH-", maxSSHLines)
}

// parseSSHIdentification splits "SSH-protoversion-softwareversion comments"
// into its parts. comments (everything after the first space) are optional
// and discarded — they're free-form vendor text (e.g. a distro suffix), not
// part of the version.
func parseSSHIdentification(line string) (protoVersion, softwareVersion string, err error) {
	rest, ok := strings.CutPrefix(line, "SSH-")
	if !ok {
		return "", "", fmt.Errorf("%w: identification line %q has no SSH- prefix", ErrUnparseable, line)
	}
	protoVersion, rest, ok = strings.Cut(rest, "-")
	if !ok {
		return "", "", fmt.Errorf("%w: identification line %q is missing the software-version separator", ErrUnparseable, line)
	}
	if softwareVersion, _, ok = strings.Cut(rest, " "); ok {
		return protoVersion, softwareVersion, nil
	}
	return protoVersion, rest, nil
}
