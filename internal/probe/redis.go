// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

// redisProbe reads redis_version out of `INFO server`, speaking RESP
// (REdis Serialization Protocol) directly over a raw TCP connection — one
// request, one reply, no client library. Credentials are optional: most
// Redis deployments have no requirepass, and Meta cannot know in advance
// whether this particular one does, so a target with none configured simply
// tries INFO first and only ever needs AUTH when the server actually asks
// for it (a NOAUTH/WRONGPASS reply maps to ErrAuth).
type redisProbe struct{}

func (redisProbe) Meta() Meta {
	return Meta{
		Product:         "redis",
		Summary:         "Redis",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthPassword}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "redis"},
	}
}

const redisDefaultPort = "6379"

func (redisProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, redisDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	br := bufio.NewReader(conn)

	if !t.Creds.IsZero() {
		if err := redisAuth(conn, br, t.Creds); err != nil {
			return obs, tcpErr(ctx, err)
		}
	}

	if _, err := conn.Write(respCommand("INFO", "server")); err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: sending INFO: %w", ErrUnreachable, err))
	}
	info, err := readRESPBulkString(br)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	version, ok := redisInfoField(info, "redis_version")
	if !ok {
		return obs, fmt.Errorf("%w: INFO server reply has no redis_version field", ErrUnparseable)
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// redisAuth sends AUTH — "AUTH password" for the classic single-secret
// form, "AUTH username password" for Redis 6+ ACL users — and requires a
// +OK reply.
func redisAuth(w io.Writer, r *bufio.Reader, creds Credentials) error {
	var cmd []byte
	if creds.Username != "" {
		cmd = respCommand("AUTH", creds.Username, creds.Password)
	} else {
		cmd = respCommand("AUTH", creds.Password)
	}
	if _, err := w.Write(cmd); err != nil {
		return fmt.Errorf("%w: sending AUTH: %w", ErrUnreachable, err)
	}

	kind, line, err := readRESPLine(r)
	if err != nil {
		return err
	}
	switch kind {
	case '+':
		return nil
	case '-':
		return fmt.Errorf("%w: %s", ErrAuth, line)
	default:
		return fmt.Errorf("%w: unexpected reply to AUTH: %c%s", ErrUnparseable, kind, line)
	}
}

// respCommand encodes args as a RESP multibulk request — the wire format
// every Redis client command uses.
func respCommand(args ...string) []byte {
	var b strings.Builder
	fmt.Fprintf(&b, "*%d\r\n", len(args))
	for _, a := range args {
		fmt.Fprintf(&b, "$%d\r\n%s\r\n", len(a), a)
	}
	return []byte(b.String())
}

// readRESPLine reads one line and splits it into its RESP type byte
// ('+' simple string, '-' error, '$' bulk string, ...) and the rest of the
// line.
func readRESPLine(r *bufio.Reader) (kind byte, rest string, err error) {
	raw, err := r.ReadString('\n')
	if err != nil {
		return 0, "", fmt.Errorf("%w: reading RESP reply: %w", ErrUnreachable, err)
	}
	raw = strings.TrimRight(raw, "\r\n")
	if raw == "" {
		return 0, "", fmt.Errorf("%w: empty RESP reply line", ErrUnparseable)
	}
	return raw[0], raw[1:], nil
}

// readRESPBulkString reads a RESP bulk string reply ("$<len>\r\n<data>\r\n"),
// verified against a live redis:7.4 server's real INFO server reply (see
// testdata/redis_7.4.11.bin) rather than assumed from the protocol spec
// alone. A NOAUTH/WRONGPASS error reply — a target with requirepass set and
// no or wrong credentials supplied — maps to ErrAuth; any other error reply
// is unexpected enough to be ErrUnparseable rather than guessed at.
func readRESPBulkString(r *bufio.Reader) (string, error) {
	kind, line, err := readRESPLine(r)
	if err != nil {
		return "", err
	}
	switch kind {
	case '-':
		if strings.HasPrefix(line, "NOAUTH") || strings.HasPrefix(line, "WRONGPASS") {
			return "", fmt.Errorf("%w: %s", ErrAuth, line)
		}
		return "", fmt.Errorf("%w: %s", ErrUnparseable, line)
	case '$':
		n, err := strconv.Atoi(line)
		if err != nil {
			return "", fmt.Errorf("%w: bad bulk string length %q: %w", ErrUnparseable, line, err)
		}
		if n < 0 {
			return "", fmt.Errorf("%w: INFO returned a nil reply", ErrUnparseable)
		}
		buf := make([]byte, n+2) // +2 for the trailing \r\n
		if _, err := io.ReadFull(r, buf); err != nil {
			return "", fmt.Errorf("%w: reading bulk string payload: %w", ErrUnreachable, err)
		}
		return string(buf[:n]), nil
	default:
		return "", fmt.Errorf("%w: unexpected RESP reply type %q", ErrUnparseable, kind)
	}
}

// redisInfoField finds "key:value" in INFO's line-oriented text reply.
func redisInfoField(info, key string) (string, bool) {
	prefix := key + ":"
	for _, line := range strings.Split(info, "\r\n") {
		if v, ok := strings.CutPrefix(line, prefix); ok {
			return v, true
		}
	}
	return "", false
}
