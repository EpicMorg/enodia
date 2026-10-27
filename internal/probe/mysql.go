// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// mysqlProbe reads the version out of MySQL's initial handshake packet
// (Protocol::HandshakeV10). The server announces its version unprompted,
// before authentication, the instant a client connects — the roadmap's own
// reason for calling mysql "the interesting one" among the non-HTTP probes,
// and D10's transport-belongs-to-the-probe principle in its purest form.
//
// After reading the version the probe answers the greeting with a throwaway
// login (completeMySQLHandshake): the version needs no credential, but a probe
// that read the greeting and hung up would be a pre-auth aborted connection,
// and enough of those from one host trip max_connect_errors and block it
// (ERR 1129). Answering turns it into a rejected authentication, which does
// not count towards the block.
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
	maxMySQLHandshake = 4096 // a real handshake is well under 150 bytes

	mysqlComQuit = 0x01
	// mysqlProbeUser is the throwaway login completeMySQLHandshake offers. It
	// never authenticates; a distinctive name just makes the rejected attempt
	// recognisable as enodia's in a server's auth log.
	mysqlProbeUser = "enodia"
)

func (mysqlProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, mysqlDefaultPort)

	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	payload, seq, err := readMySQLPacket(conn)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}
	version, verr := mysqlVersionFromPayload(payload)
	if verr == nil {
		// A real greeting: answer it so this connection is not an aborted
		// pre-auth one, even if the product check below then rejects it.
		completeMySQLHandshake(conn, seq)
	}
	if verr != nil {
		return obs, tcpErr(ctx, verr)
	}

	// product: mysql pointed at a MariaDB server is exactly the kind of
	// mismatch D9 wants caught, not silently recorded as a MySQL fact.
	if unmasked, ok := mariadbServerVersion(version); ok {
		return obs, fmt.Errorf("%w: this server is MariaDB (%s), not MySQL", ErrNotSupported, unmasked)
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// readMySQLHandshakeVersion reads one MySQL packet and returns its version,
// rejecting a MariaDB server's reply (see mariadbServerVersion). It is the
// version-only path used by the unit tests; the probes read the packet and its
// sequence number directly so they can answer the greeting.
func readMySQLHandshakeVersion(r io.Reader) (string, error) {
	version, err := readMySQLProtocolVersion(r)
	if err != nil {
		return "", err
	}
	if unmasked, ok := mariadbServerVersion(version); ok {
		return "", fmt.Errorf("%w: this server is MariaDB (%s), not MySQL", ErrNotSupported, unmasked)
	}
	return version, nil
}

// mariadbServerVersion reports whether a handshake version string is
// MariaDB's, and returns it without the compatibility mask. Two shapes,
// both confirmed live:
//   - MariaDB 10.x masks its real version behind "5.5.5-" for MySQL
//     clients that predate its own version scheme:
//     "5.5.5-10.11.19-MariaDB-ubu2204".
//   - MariaDB 11.0+ dropped the mask: "11.4.13-MariaDB-ubu2404",
//     "12.3.3-MariaDB-ubu2404" (mariadb:11.4 and :12 images, and real
//     11.4/12.3 servers that mysqlProbe had been recording as MySQL).
//     The "-MariaDB" part of the version is then the only signal.
func mariadbServerVersion(version string) (string, bool) {
	if unmasked, ok := strings.CutPrefix(version, "5.5.5-"); ok {
		return unmasked, true
	}
	if strings.Contains(strings.ToLower(version), "-mariadb") {
		return version, true
	}
	return "", false
}

// readMySQLProtocolVersion reads one MySQL packet and extracts the version.
func readMySQLProtocolVersion(r io.Reader) (string, error) {
	payload, _, err := readMySQLPacket(r)
	if err != nil {
		return "", err
	}
	return mysqlVersionFromPayload(payload)
}

// readMySQLPacket reads one MySQL protocol packet: a 4-byte header (3-byte
// little-endian length + 1-byte sequence number) followed by the payload.
func readMySQLPacket(r io.Reader) (payload []byte, seq byte, err error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, 0, fmt.Errorf("%w: reading handshake header: %w", ErrUnreachable, err)
	}
	length := int(header[0]) | int(header[1])<<8 | int(header[2])<<16
	if length <= 0 || length > maxMySQLHandshake {
		return nil, 0, fmt.Errorf("%w: implausible handshake packet length %d", ErrUnparseable, length)
	}
	payload = make([]byte, length)
	if _, err := io.ReadFull(r, payload); err != nil {
		return nil, 0, fmt.Errorf("%w: reading handshake payload: %w", ErrUnreachable, err)
	}
	return payload, header[3], nil
}

// mysqlVersionFromPayload extracts the server version from a
// Protocol::HandshakeV10 payload:
//
//	1 byte   protocol version (0x0a)
//	string   server version, NUL-terminated   <- this is all we need
//	4 bytes  connection ID
//	...      auth-plugin-data and capability flags, ignored
//
// verified against a live MySQL 8.0 server's real handshake packet (see
// testdata/mysql_8.0.46.bin). Shared by mysqlProbe and mariadbProbe: both
// speak this identical wire format and only differ in whether the version
// string is MariaDB's (mariadbServerVersion).
func mysqlVersionFromPayload(payload []byte) (string, error) {
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
	return string(payload[1 : 1+end]), nil
}

// completeMySQLHandshake answers the server's greeting with a throwaway login
// so the connection is recorded as a rejected authentication, not a pre-auth
// aborted one — the latter is what accrues towards max_connect_errors and
// eventually blocks the host (ERR 1129, confirmed live: a read-and-hang-up
// probe raises Aborted_connects_preauth, a completed handshake does not).
//
// The version has already been read from the greeting, so this is courtesy
// only: every error is ignored, and the caller returns the version regardless.
func completeMySQLHandshake(conn net.Conn, greetSeq byte) {
	if writeMySQLPacket(conn, greetSeq+1, mysqlHandshakeResponse(mysqlProbeUser)) != nil {
		return
	}
	payload, seq, err := readMySQLPacket(conn)
	if err != nil {
		return
	}
	// 0xfe is an AuthSwitchRequest: MySQL 8's default caching_sha2_password
	// asks the client to switch even for an unknown user (so the reply does
	// not reveal whether the user exists). An empty response reaches the same
	// Access-denied result without computing any auth data.
	if len(payload) > 0 && payload[0] == 0xfe {
		if writeMySQLPacket(conn, seq+1, nil) == nil {
			_, _, _ = readMySQLPacket(conn)
		}
	}
	_ = writeMySQLPacket(conn, 0, []byte{mysqlComQuit})
}

// writeMySQLPacket frames payload as one MySQL protocol packet and writes it.
func writeMySQLPacket(w io.Writer, seq byte, payload []byte) error {
	buf := make([]byte, 4+len(payload))
	buf[0] = byte(len(payload))
	buf[1] = byte(len(payload) >> 8)
	buf[2] = byte(len(payload) >> 16)
	buf[3] = seq
	copy(buf[4:], payload)
	_, err := w.Write(buf)
	return err
}

// mysqlHandshakeResponse builds a HandshakeResponse41 for user with an empty
// password and no database. The capability set is the minimum a modern server
// accepts (PROTOCOL_41 + SECURE_CONNECTION + PLUGIN_AUTH); the empty auth
// response and mysql_native_password plugin name make the server answer with
// Access denied (or, on MySQL 8, an AuthSwitchRequest first). Confirmed live
// against MySQL 8.0 and MariaDB 10.11/11.4.
func mysqlHandshakeResponse(user string) []byte {
	const (
		clientLongPassword     = 0x00000001
		clientProtocol41       = 0x00000200
		clientSecureConnection = 0x00008000
		clientPluginAuth       = 0x00080000
	)
	caps := uint32(clientLongPassword | clientProtocol41 | clientSecureConnection | clientPluginAuth)

	b := make([]byte, 0, 64)
	b = binary.LittleEndian.AppendUint32(b, caps)
	b = binary.LittleEndian.AppendUint32(b, 0xffffff) // max packet size
	b = append(b, 45)                                 // character set: utf8mb4_general_ci
	b = append(b, make([]byte, 23)...)                // reserved
	b = append(b, user...)
	b = append(b, 0)                          // username NUL terminator
	b = append(b, 0)                          // auth-response length = 0 (empty password)
	b = append(b, "mysql_native_password"...) // client auth plugin
	b = append(b, 0)
	return b
}
