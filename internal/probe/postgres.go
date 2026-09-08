// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // required by the wire protocol's own AuthenticationMD5Password, not our choice
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"slices"
	"strconv"
	"strings"
	"time"
)

// postgresProbe authenticates (trust, cleartext, MD5 or SCRAM-SHA-256 — no
// credential is required unless the server actually asks for one) and reads
// server_version out of the ParameterStatus messages every PostgreSQL
// backend sends automatically right after authentication succeeds. No
// explicit "SHOW server_version" query is needed: the protocol already
// delivers it for free, before the connection is even ready to accept one.
//
// SCRAM-SHA-256 is the default authentication method on any PostgreSQL 14+
// server (and commonly on 10-13 too), so supporting only trust/cleartext/
// MD5 would leave this probe unable to reach most real deployments —
// verified by pointing `POSTGRES_HOST_AUTH_METHOD=md5` at a live postgres:16
// container and observing it still demand SCRAM. The whole exchange
// (including the hand-rolled single-block PBKDF2-HMAC-SHA256, since SCRAM
// only ever needs exactly one block) was validated against that live server
// before being ported to Go: the computed server-signature matched the
// server's own byte for byte.
type postgresProbe struct{}

func (postgresProbe) Meta() Meta {
	return Meta{
		Product:         "postgresql",
		Aliases:         []string{"postgres"},
		Summary:         "PostgreSQL",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthPassword}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "postgresql"},
	}
}

const (
	postgresDefaultPort     = "5432"
	postgresProtocolVersion = 196608 // 3.0: major<<16 | minor
	postgresDefaultUsername = "postgres"
	maxPostgresMessage      = 1 << 20 // generous; real messages here are tiny
)

func (postgresProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, postgresDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	username := t.Creds.Username
	if username == "" {
		username = postgresDefaultUsername
	}
	// database defaults to the same value as username server-side when
	// absent; being explicit here means we never depend on that default.
	if _, err := conn.Write(postgresStartupMessage(username, username)); err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: sending startup message: %w", ErrUnreachable, err))
	}

	version, err := postgresAuthenticateAndReadVersion(conn, conn, username, t.Creds.Password)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func postgresStartupMessage(user, database string) []byte {
	var params bytes.Buffer
	params.WriteString("user\x00")
	params.WriteString(user)
	params.WriteByte(0)
	params.WriteString("database\x00")
	params.WriteString(database)
	params.WriteByte(0)
	params.WriteByte(0) // terminates the parameter list

	msg := make([]byte, 0, 8+params.Len())
	msg = binary.BigEndian.AppendUint32(msg, uint32(8+params.Len())) //nolint:gosec // a startup message is a few dozen bytes, nowhere near uint32's range
	msg = binary.BigEndian.AppendUint32(msg, postgresProtocolVersion)
	return append(msg, params.Bytes()...)
}

// postgresMessage frames a frontend message: 1 byte type, Int32 length
// (includes itself), payload.
func postgresMessage(kind byte, payload []byte) []byte {
	msg := make([]byte, 0, 5+len(payload))
	msg = append(msg, kind)
	msg = binary.BigEndian.AppendUint32(msg, uint32(4+len(payload))) //nolint:gosec // every message this probe sends is a handful of bytes, nowhere near uint32's range
	return append(msg, payload...)
}

// postgresReadMessage reads one backend message: 1 byte type, Int32 length
// (includes itself), payload.
func postgresReadMessage(r io.Reader) (kind byte, payload []byte, err error) {
	header := make([]byte, 5)
	if _, err := io.ReadFull(r, header); err != nil {
		return 0, nil, fmt.Errorf("%w: reading message header: %w", ErrUnreachable, err)
	}
	length := binary.BigEndian.Uint32(header[1:5])
	if length < 4 || length > maxPostgresMessage {
		return 0, nil, fmt.Errorf("%w: implausible message length %d", ErrUnparseable, length)
	}
	payload = make([]byte, length-4)
	if _, err := io.ReadFull(r, payload); err != nil {
		return 0, nil, fmt.Errorf("%w: reading message payload: %w", ErrUnreachable, err)
	}
	return header[0], payload, nil
}

// postgresAuthenticateAndReadVersion drives the authentication exchange to
// completion, then reads ParameterStatus messages until it finds
// server_version. The connection is simply closed afterward (by the
// caller's dialTCP cleanup) rather than drained to ReadyForQuery — same as
// every other non-HTTP probe here, an abrupt close mid-protocol is fine.
func postgresAuthenticateAndReadVersion(w io.Writer, r io.Reader, username, password string) (string, error) {
	kind, payload, err := postgresReadMessage(r)
	if err != nil {
		return "", err
	}
	if kind == 'E' {
		return "", fmt.Errorf("%w: %s", ErrAuth, postgresErrorMessage(payload))
	}
	if kind != 'R' {
		return "", fmt.Errorf("%w: expected an authentication request, got %q", ErrUnparseable, kind)
	}
	if err := postgresHandleAuth(w, r, payload, username, password); err != nil {
		return "", err
	}

	for {
		kind, payload, err := postgresReadMessage(r)
		if err != nil {
			return "", err
		}
		switch kind {
		case 'S':
			if name, value, ok := postgresSplitCString2(payload); ok && name == "server_version" {
				return value, nil
			}
		case 'E':
			return "", fmt.Errorf("%w: %s", ErrAuth, postgresErrorMessage(payload))
		case 'Z':
			return "", fmt.Errorf("%w: server never reported server_version", ErrUnparseable)
		}
	}
}

func postgresHandleAuth(w io.Writer, r io.Reader, payload []byte, username, password string) error {
	if len(payload) < 4 {
		return fmt.Errorf("%w: authentication message has no status code", ErrUnparseable)
	}
	switch code := binary.BigEndian.Uint32(payload[:4]); code {
	case 0: // AuthenticationOk
		return nil
	case 3: // AuthenticationCleartextPassword
		return postgresSendPasswordAndExpectOK(w, r, []byte(password))
	case 5: // AuthenticationMD5Password
		if len(payload) < 8 {
			return fmt.Errorf("%w: AuthenticationMD5Password message is missing its salt", ErrUnparseable)
		}
		return postgresSendPasswordAndExpectOK(w, r, []byte(postgresMD5Password(username, password, payload[4:8])))
	case 10: // AuthenticationSASL
		return postgresSCRAMSHA256(w, r, payload[4:], password)
	default:
		return fmt.Errorf("%w: unsupported authentication method (code %d)", ErrNotSupported, code)
	}
}

func postgresSendPasswordAndExpectOK(w io.Writer, r io.Reader, password []byte) error {
	if _, err := w.Write(postgresMessage('p', append(password, 0))); err != nil {
		return fmt.Errorf("%w: sending password: %w", ErrUnreachable, err)
	}
	return postgresExpectAuthOK(r)
}

func postgresExpectAuthOK(r io.Reader) error {
	kind, payload, err := postgresReadMessage(r)
	if err != nil {
		return err
	}
	if kind == 'E' {
		return fmt.Errorf("%w: %s", ErrAuth, postgresErrorMessage(payload))
	}
	if kind != 'R' || len(payload) < 4 || binary.BigEndian.Uint32(payload[:4]) != 0 {
		return fmt.Errorf("%w: password was not accepted", ErrAuth)
	}
	return nil
}

// postgresMD5Password implements Postgres's specific MD5 challenge:
// "md5" + md5hex(md5hex(password+username) + salt).
func postgresMD5Password(username, password string, salt []byte) string {
	inner := md5.Sum([]byte(password + username)) //nolint:gosec // the protocol defines MD5 here, not a security choice of ours
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...)) //nolint:gosec // same
	return "md5" + hex.EncodeToString(outer[:])
}

// postgresSCRAMSHA256 runs the SCRAM-SHA-256 exchange (RFC 5802/7677)
// without channel binding ("SCRAM-SHA-256", not "-PLUS" — this probe never
// negotiates TLS, so there is no channel to bind to). Postgres's one
// deviation from generic SCRAM: the client-first message's "n=" field is
// left empty rather than carrying the username, since the username was
// already sent in the startup message.
func postgresSCRAMSHA256(w io.Writer, r io.Reader, mechanismsPayload []byte, password string) error {
	mechanisms := strings.Split(strings.TrimRight(string(mechanismsPayload), "\x00"), "\x00")
	if !slices.Contains(mechanisms, "SCRAM-SHA-256") {
		return fmt.Errorf("%w: server offered no SCRAM-SHA-256 (offered %v)", ErrNotSupported, mechanisms)
	}

	nonceBytes := make([]byte, 18)
	if _, err := rand.Read(nonceBytes); err != nil {
		return fmt.Errorf("%w: generating client nonce: %w", ErrUnreachable, err)
	}
	clientNonce := base64.StdEncoding.EncodeToString(nonceBytes)

	const gs2Header = "n,,"
	clientFirstBare := "n=,r=" + clientNonce
	initial := postgresSASLInitialResponse("SCRAM-SHA-256", []byte(gs2Header+clientFirstBare))
	if _, err := w.Write(postgresMessage('p', initial)); err != nil {
		return fmt.Errorf("%w: sending SCRAM client-first: %w", ErrUnreachable, err)
	}

	serverFirst, err := postgresExpectSASLPayload(r, 11) // AuthenticationSASLContinue
	if err != nil {
		return err
	}
	fields, err := postgresParseSCRAMFields(serverFirst)
	if err != nil {
		return err
	}
	serverNonce, salt64, iterStr := fields["r"], fields["s"], fields["i"]
	if serverNonce == "" || salt64 == "" || iterStr == "" || !strings.HasPrefix(serverNonce, clientNonce) {
		return fmt.Errorf("%w: malformed or mismatched SCRAM server-first message", ErrUnparseable)
	}
	salt, err := base64.StdEncoding.DecodeString(salt64)
	if err != nil {
		return fmt.Errorf("%w: bad SCRAM salt: %w", ErrUnparseable, err)
	}
	iterations, err := strconv.Atoi(iterStr)
	if err != nil || iterations <= 0 {
		return fmt.Errorf("%w: bad SCRAM iteration count %q", ErrUnparseable, iterStr)
	}

	saltedPassword := pbkdf2HMACSHA256Once([]byte(password), salt, iterations)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)

	clientFinalWithoutProof := "c=" + base64.StdEncoding.EncodeToString([]byte(gs2Header)) + ",r=" + serverNonce
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	clientSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	clientProof := xorBytes(clientKey, clientSignature)

	clientFinal := clientFinalWithoutProof + ",p=" + base64.StdEncoding.EncodeToString(clientProof)
	if _, err := w.Write(postgresMessage('p', []byte(clientFinal))); err != nil {
		return fmt.Errorf("%w: sending SCRAM client-final: %w", ErrUnreachable, err)
	}

	serverFinal, err := postgresExpectSASLPayload(r, 12) // AuthenticationSASLFinal
	if err != nil {
		return err
	}
	finalFields, err := postgresParseSCRAMFields(serverFinal)
	if err != nil {
		return err
	}
	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	expectedSignature := hmacSHA256(serverKey, []byte(authMessage))
	gotSignature, err := base64.StdEncoding.DecodeString(finalFields["v"])
	if err != nil || !hmac.Equal(gotSignature, expectedSignature) {
		return fmt.Errorf("%w: SCRAM server signature did not verify", ErrUnparseable)
	}

	return postgresExpectAuthOK(r)
}

// postgresExpectSASLPayload reads one authentication message and requires
// it to carry the given status code (11 = AuthenticationSASLContinue,
// 12 = AuthenticationSASLFinal), returning the bytes after the code.
func postgresExpectSASLPayload(r io.Reader, wantCode uint32) (string, error) {
	kind, payload, err := postgresReadMessage(r)
	if err != nil {
		return "", err
	}
	if kind == 'E' {
		return "", fmt.Errorf("%w: %s", ErrAuth, postgresErrorMessage(payload))
	}
	if kind != 'R' || len(payload) < 4 || binary.BigEndian.Uint32(payload[:4]) != wantCode {
		return "", fmt.Errorf("%w: expected SASL status %d", ErrUnparseable, wantCode)
	}
	return string(payload[4:]), nil
}

// postgresSASLInitialResponse builds a SASLInitialResponse body: mechanism
// name (NUL-terminated), Int32 response length, response bytes.
func postgresSASLInitialResponse(mechanism string, response []byte) []byte {
	buf := make([]byte, 0, len(mechanism)+1+4+len(response))
	buf = append(buf, mechanism...)
	buf = append(buf, 0)
	buf = binary.BigEndian.AppendUint32(buf, uint32(len(response))) //nolint:gosec // a SCRAM client-first message is well under 100 bytes, nowhere near uint32's range
	return append(buf, response...)
}

func postgresParseSCRAMFields(s string) (map[string]string, error) {
	fields := make(map[string]string)
	for _, part := range strings.Split(s, ",") {
		name, value, ok := strings.Cut(part, "=")
		if !ok {
			return nil, fmt.Errorf("%w: malformed SCRAM field %q", ErrUnparseable, part)
		}
		fields[name] = value
	}
	return fields, nil
}

// postgresSplitCString2 splits a ParameterStatus payload ("name\x00value\x00")
// into its two NUL-terminated strings.
func postgresSplitCString2(payload []byte) (name, value string, ok bool) {
	parts := bytes.SplitN(bytes.TrimRight(payload, "\x00"), []byte{0}, 2)
	if len(parts) != 2 {
		return "", "", false
	}
	return string(parts[0]), string(parts[1]), true
}

// postgresErrorMessage extracts the 'M' (human-readable message) field from
// an ErrorResponse payload, which is a sequence of (1-byte code + NUL-
// terminated string) fields.
func postgresErrorMessage(payload []byte) string {
	for _, field := range bytes.Split(payload, []byte{0}) {
		if len(field) > 1 && field[0] == 'M' {
			return string(field[1:])
		}
	}
	return "unspecified error"
}

func hmacSHA256(key, msg []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(msg)
	return h.Sum(nil)
}

// pbkdf2HMACSHA256Once implements PBKDF2 (RFC 8018) for the one case SCRAM
// ever needs: a single block, since the requested key length always equals
// the PRF's own output size (32 bytes for SHA-256). Hand-rolled rather than
// pulled in from golang.org/x/crypto/pbkdf2 — that package's full
// multi-block generality buys nothing here, and adding a dependency for 12
// lines of iterated HMAC would just widen this tool's supply-chain surface
// for no benefit.
func pbkdf2HMACSHA256Once(password, salt []byte, iterations int) []byte {
	prf := hmac.New(sha256.New, password)
	prf.Write(salt)
	prf.Write([]byte{0, 0, 0, 1})
	u := prf.Sum(nil)
	result := append([]byte(nil), u...)
	for i := 1; i < iterations; i++ {
		prf.Reset()
		prf.Write(u)
		u = prf.Sum(nil)
		for j := range result {
			result[j] ^= u[j]
		}
	}
	return result
}

func xorBytes(a, b []byte) []byte {
	out := make([]byte, len(a))
	for i := range out {
		out[i] = a[i] ^ b[i]
	}
	return out
}
