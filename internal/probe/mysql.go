// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// mysqlProbe reads the version out of MySQL's initial handshake packet
// (Protocol::HandshakeV10). No request is ever sent: the server announces
// its version unprompted, before authentication, the instant a client
// connects — the roadmap's own reason for calling mysql "the interesting
// one" among the non-HTTP probes, and D10's transport-belongs-to-the-probe
// principle in its purest form, since there is no HTTP request to make at
// all.
type mysqlProbe struct{}

func (mysqlProbe) Meta() Meta {
	return Meta{
		Product: "mysql",
		Summary: "MySQL Server",
		// The handshake is read before any authentication step, so no
		// credential is ever required to observe the version.
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "mysql"},
		// No DefaultScheme: a bare "host:port" is the address, not a URL —
		// there is no scheme to be missing.
	}
}

const (
	mysqlDefaultPort  = "3306"
	mysqlReadTimeout  = 10 * time.Second // last-resort default if Target.Timeout is unset
	maxMySQLHandshake = 4096             // a real handshake is well under 150 bytes
)

func (mysqlProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := mysqlAddress(t.Address)

	var d net.Dialer
	conn, err := d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return obs, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer conn.Close()

	timeout := t.Timeout
	if timeout <= 0 {
		timeout = mysqlReadTimeout
	}
	_ = conn.SetReadDeadline(time.Now().Add(timeout))

	// DialContext only covers the dial; a blocking Read afterwards does not
	// observe ctx cancellation on its own. Closing the connection when ctx
	// is done unblocks it immediately instead of waiting out the deadline —
	// the same reason cmd/enodia wires SIGINT/SIGTERM into its root context.
	done := make(chan struct{})
	defer close(done)
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	version, err := readMySQLHandshakeVersion(conn)
	if err != nil {
		if ctx.Err() != nil {
			return obs, fmt.Errorf("%w: %w", ErrUnreachable, ctx.Err())
		}
		return obs, err
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// mysqlAddress defaults the port. Raw TCP targets carry no scheme, so
// probe.HasScheme-style resolution does not apply here.
func mysqlAddress(addr string) string {
	addr = strings.TrimPrefix(addr, "tcp://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, mysqlDefaultPort)
	}
	return addr
}

// readMySQLHandshakeVersion reads one MySQL packet and extracts the version
// string from a Protocol::HandshakeV10 payload:
//
//	1 byte   protocol version (0x0a)
//	string   server version, NUL-terminated   <- this is all we need
//	4 bytes  connection ID
//	...      auth-plugin-data and capability flags, ignored
//
// verified against a live MySQL 8.0 server's real handshake packet (see
// testdata/mysql_8.0.46.bin) rather than assumed from the protocol docs
// alone.
func readMySQLHandshakeVersion(r io.Reader) (string, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", fmt.Errorf("%w: reading handshake header: %w", ErrUnreachable, err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length <= 0 || length > maxMySQLHandshake {
		return "", fmt.Errorf("%w: implausible handshake packet length %d", ErrUnparseable, length)
	}

	payload := make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return "", fmt.Errorf("%w: reading handshake payload: %w", ErrUnreachable, err)
	}

	// An ERR packet (0xff) means the server refused the connection at the
	// protocol level — too many connections, host blocked, and the like —
	// which is an environmental reachability problem, not a handshake to
	// parse or a sign of the wrong product.
	if payload[0] == 0xff {
		var code uint16
		if len(payload) >= 3 {
			code = uint16(payload[1]) | uint16(payload[2])<<8
		}
		return "", fmt.Errorf("%w: server sent an ERR packet (code %d) instead of a handshake", ErrUnreachable, code)
	}
	if payload[0] != 0x0a {
		return "", fmt.Errorf("%w: not a MySQL protocol-10 handshake (first byte %#x)", ErrNotSupported, payload[0])
	}

	end := bytes.IndexByte(payload[1:], 0)
	if end < 0 {
		return "", fmt.Errorf("%w: handshake version string is not NUL-terminated", ErrUnparseable)
	}
	version := string(payload[1 : 1+end])

	// MariaDB masks its real version behind "5.5.5-" for MySQL clients that
	// predate MariaDB's own version scheme (confirmed still true on a
	// current MariaDB 10.11 image, not assumed from older documentation).
	// product: mysql pointed at a MariaDB server is exactly the kind of
	// mismatch D9 wants caught, not silently recorded as a MySQL fact.
	if unmasked, ok := strings.CutPrefix(version, "5.5.5-"); ok {
		return "", fmt.Errorf("%w: this server is MariaDB (%s), not MySQL", ErrNotSupported, unmasked)
	}
	return version, nil
}
