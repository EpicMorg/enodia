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

// memcachedProbe sends the text protocol's "version" command over raw TCP
// and reads the one-line reply, "VERSION 1.6.45" (confirmed live against
// memcached:1.6, see testdata/memcached_1.6.45.bin). The text protocol has
// no authentication, so there are no credentials to offer. A server
// started with SASL (-S) speaks only the binary protocol and answers the
// text command with an error; that is reported as ErrNotSupported rather
// than guessed at.
type memcachedProbe struct{}

func (memcachedProbe) Meta() Meta {
	return Meta{
		Product:         "memcached",
		Summary:         "memcached",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "memcached"},
	}
}

const memcachedDefaultPort = "11211"

var memcachedVersionPattern = regexp.MustCompile(`^VERSION (\d+(?:\.\d+)+\S*)$`)

func (memcachedProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, memcachedDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	if _, err := conn.Write([]byte("version\r\n")); err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: sending version: %w", ErrUnreachable, err))
	}
	line, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: reading version reply: %w", ErrUnreachable, err))
	}
	version, err := parseMemcachedVersion(line)
	if err != nil {
		return obs, err
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func parseMemcachedVersion(line string) (string, error) {
	line = strings.TrimRight(line, "\r\n")
	if m := memcachedVersionPattern.FindStringSubmatch(line); m != nil {
		return m[1], nil
	}
	if strings.HasPrefix(line, "ERROR") || strings.HasPrefix(line, "CLIENT_ERROR") || strings.HasPrefix(line, "SERVER_ERROR") {
		return "", fmt.Errorf("%w: text-protocol version refused (%q) — binary-only/SASL memcached isn't supported", ErrNotSupported, line)
	}
	return "", fmt.Errorf("%w: not a memcached version reply: %q", ErrUnparseable, line)
}
