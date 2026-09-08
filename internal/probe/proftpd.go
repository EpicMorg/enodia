// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// proftpdProbe reads the FTP greeting (RFC 959's "220" reply) every server
// sends unprompted on connect, and looks for a version inside it.
//
// Read proftpd's own src/session.c (pr_session_send_banner): with no
// ServerIdent directive configured at all — confirmed to be the actual
// out-of-the-box default, not a hardening step someone took — the greeting
// is "ProFTPD Server (<ServerName>) [<address>]", carrying no version.
// Confirmed live twice: against a real production ftp.saber3d.net host and
// a fresh instantlinux/proftpd container's default config, both answered
// exactly that shape. The version only appears if an admin explicitly
// configures `ServerIdent on "... %{version} ..."` — confirmed live too,
// by adding that directive to the same container and observing the real
// substitution: "ProFTPD 1.3.9c ready at 127.0.0.1". So this probe's
// "no version found" case is the common one, not the exception — same
// ErrNotSupported family as nginx's server_tokens off, just the opposite
// default polarity (opt-in exposure here, not opt-out).
type proftpdProbe struct{}

func (proftpdProbe) Meta() Meta {
	return Meta{
		Product: "proftpd",
		Summary: "ProFTPD",
		Auth:    AuthSpec{Required: false},
		// No DefaultScheme: FTP has no URL scheme concept here (D10), same
		// as mysql/redis/mongodb.
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "proftpd"},
	}
}

const (
	proftpdDefaultPort  = "21"
	maxFTPGreetingLines = 50 // RFC 959 multi-line "220-" continuations before the final "220 " line
)

// proftpdVersionPattern requires "ProFTPD" immediately before the version
// number, not just a bare version anywhere in an admin's free-form
// ServerIdent text — confirmed against the real substituted banner above.
var proftpdVersionPattern = regexp.MustCompile(`\bProFTPD\s+(\d+\.\d+\.\d+[A-Za-z0-9]*)\b`)

func (proftpdProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, proftpdDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	greeting, err := readFTPGreeting(bufio.NewReader(conn))
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	if !strings.Contains(greeting, "ProFTPD") {
		return obs, fmt.Errorf("%w: greeting %q does not mention ProFTPD "+
			"(either the wrong product, or ServerIdent is off)", ErrNotSupported, greeting)
	}
	m := proftpdVersionPattern.FindStringSubmatch(greeting)
	if m == nil {
		return obs, fmt.Errorf("%w: greeting %q confirms ProFTPD but carries no version "+
			"(the out-of-the-box default: ServerIdent must explicitly include %%{version})",
			ErrNotSupported, greeting)
	}

	obs.Version = m[1]
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// readFTPGreeting reads RFC 959 reply lines until the final "220 " one,
// skipping any "220-" continuation lines a DisplayConnect banner file can
// add before it.
func readFTPGreeting(r *bufio.Reader) (string, error) {
	for i := 0; i < maxFTPGreetingLines; i++ {
		line, err := r.ReadString('\n')
		if err != nil {
			return "", fmt.Errorf("%w: reading FTP greeting: %w", ErrUnreachable, err)
		}
		line = strings.TrimRight(line, "\r\n")
		switch {
		case strings.HasPrefix(line, "220 "):
			return line, nil
		case strings.HasPrefix(line, "220-"):
			continue
		default:
			return "", fmt.Errorf("%w: unexpected FTP greeting line %q", ErrUnparseable, line)
		}
	}
	return "", fmt.Errorf("%w: no final \"220 \" line in the first %d lines", ErrUnparseable, maxFTPGreetingLines)
}
