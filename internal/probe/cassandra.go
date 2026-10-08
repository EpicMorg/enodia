// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"time"
)

// cassandraProbe reads release_version from system.local over the CQL
// native protocol (v4), with no driver: STARTUP, then — only when the
// server answers AUTHENTICATE — one SASL PLAIN AUTH_RESPONSE, then a single
// QUERY. Confirmed live: cassandra:3.11 (3.11.19, no auth: STARTUP ->
// READY) and cassandra:5.0 with PasswordAuthenticator (5.0.9: STARTUP ->
// AUTHENTICATE -> AUTH_SUCCESS); the real frames are in
// testdata/cassandra_*.bin. OPTIONS/SUPPORTED, the one pre-auth exchange,
// carries the CQL and protocol versions but not the server's.
//
// v4 because it is the one version every live Cassandra speaks: 3.x and
// 4.x through 5.0 accept it, and 3.11 refused v5 outright ("Beta version
// of the protocol used"). Cassandra 2.x (v3 at most) is long out of
// support and not attempted.
type cassandraProbe struct{}

func (cassandraProbe) Meta() Meta {
	return Meta{
		Product:         "cassandra",
		Summary:         "Apache Cassandra (CQL native protocol)",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthPassword}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "apache-cassandra"},
	}
}

const (
	cassandraDefaultPort = "9042"
	cqlVersion4          = 0x04
	cqlResponseFlag      = 0x80

	cqlOpError        = 0x00
	cqlOpStartup      = 0x01
	cqlOpReady        = 0x02
	cqlOpAuthenticate = 0x03
	cqlOpQuery        = 0x07
	cqlOpResult       = 0x08
	cqlOpAuthResponse = 0x0F
	cqlOpAuthSuccess  = 0x10

	cqlResultRows = 0x0002
	cqlErrBadCred = 0x0100

	// cqlMaxFrame caps a response body; the replies read here are a few
	// hundred bytes.
	cqlMaxFrame = 1 << 20
)

const cassandraVersionQuery = "SELECT release_version FROM system.local"

func (cassandraProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, cassandraDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	version, err := cassandraReleaseVersion(conn, t.Creds)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}
	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func cassandraReleaseVersion(conn net.Conn, creds Credentials) (string, error) {
	if err := writeCQLFrame(conn, 0, cqlOpStartup, cqlStringMap(map[string]string{"CQL_VERSION": "3.0.0"})); err != nil {
		return "", err
	}
	op, body, err := readCQLFrame(conn)
	if err != nil {
		return "", err
	}
	switch op {
	case cqlOpReady:
	case cqlOpAuthenticate:
		if creds.IsZero() {
			authenticator, _ := cqlReadString(body)
			return "", fmt.Errorf("%w: server requires authentication (%s)", ErrAuth, authenticator)
		}
		token := append(append(append([]byte{0}, creds.Username...), 0), creds.Password...)
		if err := writeCQLFrame(conn, 1, cqlOpAuthResponse, cqlBytes(token)); err != nil {
			return "", err
		}
		op, body, err = readCQLFrame(conn)
		if err != nil {
			return "", err
		}
		if op == cqlOpError {
			return "", cqlError(body)
		}
		if op != cqlOpAuthSuccess {
			return "", fmt.Errorf("%w: unexpected CQL opcode 0x%02x after AUTH_RESPONSE (only SASL PLAIN is supported)", ErrNotSupported, op)
		}
	case cqlOpError:
		return "", cqlError(body)
	default:
		return "", fmt.Errorf("%w: unexpected CQL opcode 0x%02x after STARTUP", ErrUnparseable, op)
	}

	query := append(cqlLongString(cassandraVersionQuery), 0x00, 0x01, 0x00) // consistency ONE, no flags
	if err := writeCQLFrame(conn, 2, cqlOpQuery, query); err != nil {
		return "", err
	}
	op, body, err = readCQLFrame(conn)
	if err != nil {
		return "", err
	}
	if op == cqlOpError {
		return "", cqlError(body)
	}
	if op != cqlOpResult {
		return "", fmt.Errorf("%w: unexpected CQL opcode 0x%02x for QUERY", ErrUnparseable, op)
	}
	return cqlSingleTextCell(body)
}

func writeCQLFrame(w io.Writer, stream uint16, op byte, body []byte) error {
	h := make([]byte, 9, 9+len(body))
	h[0] = cqlVersion4
	binary.BigEndian.PutUint16(h[2:4], stream)
	h[4] = op
	binary.BigEndian.PutUint32(h[5:9], uint32(len(body))) //nolint:gosec // bodies built here are tiny
	if _, err := w.Write(append(h, body...)); err != nil {
		return fmt.Errorf("%w: sending CQL frame: %w", ErrUnreachable, err)
	}
	return nil
}

func readCQLFrame(r io.Reader) (op byte, body []byte, err error) {
	var h [9]byte
	if _, err := io.ReadFull(r, h[:]); err != nil {
		return 0, nil, fmt.Errorf("%w: reading CQL frame header: %w", ErrUnreachable, err)
	}
	if h[0] != cqlVersion4|cqlResponseFlag {
		return 0, nil, fmt.Errorf("%w: not a CQL v4 response (version byte 0x%02x)", ErrNotSupported, h[0])
	}
	n := binary.BigEndian.Uint32(h[5:9])
	if n > cqlMaxFrame {
		return 0, nil, fmt.Errorf("%w: CQL frame of %d bytes", ErrUnparseable, n)
	}
	body = make([]byte, n)
	if _, err := io.ReadFull(r, body); err != nil {
		return 0, nil, fmt.Errorf("%w: reading CQL frame body: %w", ErrUnreachable, err)
	}
	return h[4], body, nil
}

// cqlError turns an ERROR body ([int] code, [string] message) into an
// error; bad credentials (0x0100) map to ErrAuth.
func cqlError(body []byte) error {
	if len(body) < 4 {
		return fmt.Errorf("%w: short CQL ERROR frame", ErrUnparseable)
	}
	code := binary.BigEndian.Uint32(body[:4])
	msg, _ := cqlReadString(body[4:])
	if code == cqlErrBadCred {
		return fmt.Errorf("%w: %s", ErrAuth, msg)
	}
	return fmt.Errorf("%w: CQL error 0x%04x: %s", ErrUnparseable, code, msg)
}

// cqlSingleTextCell reads a Rows RESULT for a one-column, one-row query
// and returns that cell as text — release_version is a varchar.
func cqlSingleTextCell(b []byte) (string, error) {
	errShort := fmt.Errorf("%w: truncated CQL Rows result", ErrUnparseable)
	u32 := func() (uint32, bool) {
		if len(b) < 4 {
			return 0, false
		}
		v := binary.BigEndian.Uint32(b[:4])
		b = b[4:]
		return v, true
	}
	skipString := func() bool {
		s, ok := cqlReadString(b)
		if !ok {
			return false
		}
		b = b[2+len(s):]
		return true
	}

	kind, ok := u32()
	if !ok {
		return "", errShort
	}
	if kind != cqlResultRows {
		return "", fmt.Errorf("%w: CQL RESULT kind %d, want Rows", ErrUnparseable, kind)
	}
	flags, ok1 := u32()
	cols, ok2 := u32()
	if !ok1 || !ok2 {
		return "", errShort
	}
	if cols != 1 {
		return "", fmt.Errorf("%w: CQL Rows result has %d columns, want 1", ErrUnparseable, cols)
	}
	if flags&0x0002 != 0 { // has_more_pages: [bytes] paging state, never set for one row
		return "", fmt.Errorf("%w: paged CQL result for a one-row query", ErrUnparseable)
	}
	if flags&0x0004 == 0 { // metadata present
		// keyspace and table: once as the global table spec (flag 0x0001)
		// or ahead of the one column — the same two strings either way.
		for range 2 {
			if !skipString() {
				return "", errShort
			}
		}
		if !skipString() || len(b) < 2 { // column name, then its type option
			return "", errShort
		}
		if typ := binary.BigEndian.Uint16(b[:2]); typ != 0x000D && typ != 0x0001 { // varchar, ascii
			return "", fmt.Errorf("%w: release_version has CQL type 0x%04x, want text", ErrUnparseable, typ)
		}
		b = b[2:]
	}
	rows, ok := u32()
	if !ok {
		return "", errShort
	}
	if rows != 1 {
		return "", fmt.Errorf("%w: system.local returned %d rows, want 1", ErrUnparseable, rows)
	}
	// [bytes]: a negative length is a null cell.
	n, ok := u32()
	if !ok {
		return "", errShort
	}
	if n == 0 || n >= 1<<31 {
		return "", fmt.Errorf("%w: empty release_version", ErrUnparseable)
	}
	if uint64(n) > uint64(len(b)) {
		return "", errShort
	}
	return string(b[:n]), nil
}

func cqlReadString(b []byte) (string, bool) {
	if len(b) < 2 {
		return "", false
	}
	n := int(binary.BigEndian.Uint16(b[:2]))
	if len(b) < 2+n {
		return "", false
	}
	return string(b[2 : 2+n]), true
}

func cqlString(s string) []byte {
	b := make([]byte, 2, 2+len(s))
	binary.BigEndian.PutUint16(b, uint16(len(s))) //nolint:gosec // only short constant strings are encoded
	return append(b, s...)
}

func cqlLongString(s string) []byte {
	b := make([]byte, 4, 4+len(s))
	binary.BigEndian.PutUint32(b, uint32(len(s))) //nolint:gosec // only short constant strings are encoded
	return append(b, s...)
}

func cqlBytes(v []byte) []byte {
	b := make([]byte, 4, 4+len(v))
	binary.BigEndian.PutUint32(b, uint32(len(v))) //nolint:gosec // a username/password pair
	return append(b, v...)
}

func cqlStringMap(m map[string]string) []byte {
	b := make([]byte, 2)
	binary.BigEndian.PutUint16(b, uint16(len(m))) //nolint:gosec // one entry
	for k, v := range m {
		b = append(append(b, cqlString(k)...), cqlString(v)...)
	}
	return b
}
