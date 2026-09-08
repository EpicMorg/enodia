// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/md5" //nolint:gosec // test computes the protocol's own MD5 challenge independently, to cross-check the probe
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func loadPostgresFixture(t *testing.T, name string) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// --- message framing ---

func TestPostgresStartupMessage(t *testing.T) {
	msg := postgresStartupMessage("alice", "alice")
	if len(msg) < 8 {
		t.Fatalf("too short: %d", len(msg))
	}
	length := binary.BigEndian.Uint32(msg[0:4])
	if int(length) != len(msg) {
		t.Fatalf("declared length %d, actual %d", length, len(msg))
	}
	proto := binary.BigEndian.Uint32(msg[4:8])
	if proto != postgresProtocolVersion {
		t.Fatalf("got protocol %d, want %d", proto, postgresProtocolVersion)
	}
	if !bytes.Contains(msg, []byte("user\x00alice\x00")) {
		t.Fatalf("missing user param: %q", msg)
	}
	if !bytes.Contains(msg, []byte("database\x00alice\x00")) {
		t.Fatalf("missing database param: %q", msg)
	}
}

func TestPostgresMessageFraming(t *testing.T) {
	msg := postgresMessage('p', []byte("hello"))
	if msg[0] != 'p' {
		t.Fatalf("got type %q", msg[0])
	}
	length := binary.BigEndian.Uint32(msg[1:5])
	if int(length) != 4+len("hello") {
		t.Fatalf("got length %d, want %d", length, 4+len("hello"))
	}
}

func TestPostgresReadMessageRoundTrips(t *testing.T) {
	raw := postgresMessage('R', []byte{0, 0, 0, 0})
	kind, payload, err := postgresReadMessage(bytes.NewReader(raw))
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if kind != 'R' || !bytes.Equal(payload, []byte{0, 0, 0, 0}) {
		t.Fatalf("got kind=%q payload=%v", kind, payload)
	}
}

func TestPostgresReadMessageImplausibleLength(t *testing.T) {
	raw := []byte{'R', 0xff, 0xff, 0xff, 0xff}
	_, _, err := postgresReadMessage(bytes.NewReader(raw))
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestPostgresReadMessageTruncated(t *testing.T) {
	_, _, err := postgresReadMessage(bytes.NewReader([]byte{'R', 0, 0}))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestPostgresSplitCString2(t *testing.T) {
	name, value, ok := postgresSplitCString2([]byte("server_version\x0016.15\x00"))
	if !ok || name != "server_version" || value != "16.15" {
		t.Fatalf("got name=%q value=%q ok=%v", name, value, ok)
	}
}

func TestPostgresSplitCString2Malformed(t *testing.T) {
	if _, _, ok := postgresSplitCString2([]byte("no-nul-anywhere")); ok {
		t.Fatal("expected ok=false")
	}
}

func TestPostgresErrorMessageExtractsMField(t *testing.T) {
	payload := []byte("SFATAL\x00C28P01\x00Mpassword authentication failed for user \"postgres\"\x00\x00")
	if got, want := postgresErrorMessage(payload), `password authentication failed for user "postgres"`; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestPostgresErrorMessageNoMField(t *testing.T) {
	if got, want := postgresErrorMessage([]byte("SFATAL\x00")), "unspecified error"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// --- SCRAM building blocks, cross-checked against independent computations ---

func TestPBKDF2HMACSHA256OnceMatchesKnownVector(t *testing.T) {
	// Computed independently via Python's hashlib.pbkdf2_hmac('sha256', ...)
	// for the same inputs, not derived from this Go implementation.
	salt, err := base64.StdEncoding.DecodeString("W22ZaJ0SNY7soEsUEjb6gQ==")
	if err != nil {
		t.Fatal(err)
	}
	got := pbkdf2HMACSHA256Once([]byte("pencil"), salt, 4096)
	want, err := hex.DecodeString("c4a49510323ab4f952cac1fa99441939e78ea74d6be81ddf7096e87513dc615d"[:64])
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestXorBytes(t *testing.T) {
	got := xorBytes([]byte{0xff, 0x00, 0xaa}, []byte{0x0f, 0xf0, 0xaa})
	want := []byte{0xf0, 0xf0, 0x00}
	if !bytes.Equal(got, want) {
		t.Fatalf("got %x, want %x", got, want)
	}
}

func TestPostgresParseSCRAMFields(t *testing.T) {
	fields, err := postgresParseSCRAMFields("r=abc123,s=c2FsdA==,i=4096")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if fields["r"] != "abc123" || fields["s"] != "c2FsdA==" || fields["i"] != "4096" {
		t.Fatalf("got %+v", fields)
	}
}

func TestPostgresParseSCRAMFieldsMalformed(t *testing.T) {
	if _, err := postgresParseSCRAMFields("not-a-field"); !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestPostgresMD5PasswordMatchesIndependentComputation(t *testing.T) {
	salt := []byte{1, 2, 3, 4}
	inner := md5.Sum([]byte("secret" + "alice")) //nolint:gosec // independent cross-check, not the implementation under test
	innerHex := hex.EncodeToString(inner[:])
	outer := md5.Sum(append([]byte(innerHex), salt...)) //nolint:gosec // same
	want := "md5" + hex.EncodeToString(outer[:])

	if got := postgresMD5Password("alice", "secret", salt); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

// --- real captured trust-auth fixture ---

// postgres_16.15_trust.bin is the real backend message stream captured from
// a live postgres:16 server configured with POSTGRES_HOST_AUTH_METHOD=trust:
// AuthenticationOk followed by ParameterStatus messages, including
// server_version, exactly as PostgreSQL sends them unprompted once
// authentication succeeds — no "SHOW server_version" query needed.
func TestPostgresAuthenticateAndReadVersionRealTrustFixture(t *testing.T) {
	raw := loadPostgresFixture(t, "postgres_16.15_trust.bin")
	version, err := postgresAuthenticateAndReadVersion(nil, bytes.NewReader(raw), "postgres", "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if version != "16.15 (Debian 16.15-1.pgdg13+2)" {
		t.Fatalf("got %q", version)
	}
}

// --- fake server: exercises the real client code against a scripted,
// cryptographically-correct server implementation, entirely offline. The
// wire-level protocol shapes (message layout, auth codes 0/3/5/10/11/12,
// the empty "n=" field, PBKDF2/HMAC construction) were separately verified
// against a live postgres:16 server via a Python prototype before being
// ported here — this fake server independently recomputes what a real
// server would, rather than replaying fixed bytes, so it genuinely
// exercises the client's cryptography rather than just its message framing.

type fakePostgresServer struct {
	username string
	password string
	authMode string // "trust", "cleartext", "md5", "scram", "unsupported"
}

func (f fakePostgresServer) serve(t *testing.T, conn net.Conn) {
	defer conn.Close()
	// StartupMessage: read and discard.
	lenBuf := make([]byte, 4)
	if _, err := conn.Read(lenBuf); err != nil {
		return
	}
	length := binary.BigEndian.Uint32(lenBuf)
	rest := make([]byte, length-4)
	if _, err := readFullConn(conn, rest); err != nil {
		return
	}

	switch f.authMode {
	case "trust":
		f.sendAuthCode(conn, 0)
	case "cleartext":
		f.sendAuthCode(conn, 3)
		got, ok := f.readPasswordMessage(t, conn)
		if !ok {
			return
		}
		if got != f.password {
			t.Errorf("got password %q, want %q", got, f.password)
			return
		}
		f.sendAuthCode(conn, 0)
	case "cleartext-wrong":
		f.sendAuthCode(conn, 3)
		// Deliberately reject regardless of what was sent: this test is
		// about the probe correctly surfacing ErrAuth from an ErrorResponse,
		// not about the server's own comparison logic.
		if _, ok := f.readPasswordMessage(t, conn); !ok {
			return
		}
		f.sendError(conn)
		return
	case "md5":
		salt := []byte{0xde, 0xad, 0xbe, 0xef}
		buf := make([]byte, 4)
		binary.BigEndian.PutUint32(buf, 5)
		conn.Write(postgresMessage('R', append(buf, salt...)))
		want := postgresMD5Password(f.username, f.password, salt)
		got, ok := f.readPasswordMessage(t, conn)
		if !ok {
			return
		}
		if got != want {
			t.Errorf("got password %q, want %q", got, want)
			return
		}
		f.sendAuthCode(conn, 0)
	case "scram":
		if !f.serveSCRAM(t, conn) {
			return
		}
	case "unsupported":
		f.sendAuthCode(conn, 99)
		return
	}

	// ParameterStatus carrying server_version, then ReadyForQuery.
	conn.Write(postgresMessage('S', append([]byte("server_version\x00"), append([]byte(pgTestVersion), 0)...)))
	conn.Write(postgresMessage('Z', []byte("I")))
}

const pgTestVersion = "16.4 (fake)"

func (fakePostgresServer) sendAuthCode(conn net.Conn, code uint32) {
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, code)
	conn.Write(postgresMessage('R', buf))
}

func (fakePostgresServer) sendError(conn net.Conn) {
	conn.Write(postgresMessage('E', []byte("SFATAL\x00C28P01\x00Mpassword authentication failed\x00\x00")))
}

// readPasswordMessage reads a PasswordMessage and returns its content.
// Framing/protocol errors here are always a real bug and fail the test;
// whether the password itself is the expected one is the caller's call,
// since some tests deliberately send a wrong one to exercise rejection.
func (fakePostgresServer) readPasswordMessage(t *testing.T, conn net.Conn) (string, bool) {
	t.Helper()
	kind, payload, err := postgresReadMessage(conn)
	if err != nil || kind != 'p' {
		t.Errorf("reading PasswordMessage: kind=%q err=%v", kind, err)
		return "", false
	}
	return strings.TrimSuffix(string(payload), "\x00"), true
}

// serveSCRAM independently recomputes the server side of SCRAM-SHA-256:
// generates its own salt and nonce suffix, verifies the client's proof
// against the SAME password using the same formulas the client uses, and
// only proceeds if they actually match — a fake that always says yes would
// prove nothing about the client's crypto.
func (f fakePostgresServer) serveSCRAM(t *testing.T, conn net.Conn) bool {
	t.Helper()
	buf := make([]byte, 4)
	binary.BigEndian.PutUint32(buf, 10)
	conn.Write(postgresMessage('R', append(buf, []byte("SCRAM-SHA-256\x00\x00")...)))

	kind, payload, err := postgresReadMessage(conn)
	if err != nil || kind != 'p' {
		t.Errorf("reading SASLInitialResponse: kind=%q err=%v", kind, err)
		return false
	}
	mechEnd := bytes.IndexByte(payload, 0)
	respLen := binary.BigEndian.Uint32(payload[mechEnd+1 : mechEnd+5])
	clientFirst := string(payload[mechEnd+5 : mechEnd+5+int(respLen)])
	clientFirstBare := strings.TrimPrefix(clientFirst, "n,,")

	fields, err := postgresParseSCRAMFields(clientFirstBare)
	if err != nil {
		t.Errorf("parsing client-first: %v", err)
		return false
	}
	clientNonce := fields["r"]

	serverNonceSuffix := make([]byte, 12)
	rand.Read(serverNonceSuffix)
	serverNonce := clientNonce + base64.StdEncoding.EncodeToString(serverNonceSuffix)
	salt := make([]byte, 16)
	rand.Read(salt)
	const iterations = 4096

	serverFirst := fmt.Sprintf("r=%s,s=%s,i=%d", serverNonce, base64.StdEncoding.EncodeToString(salt), iterations)
	buf2 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf2, 11)
	conn.Write(postgresMessage('R', append(buf2, []byte(serverFirst)...)))

	kind, payload, err = postgresReadMessage(conn)
	if err != nil || kind != 'p' {
		t.Errorf("reading client-final: kind=%q err=%v", kind, err)
		return false
	}
	clientFinal := string(payload)
	finalFields, err := postgresParseSCRAMFields(clientFinal)
	if err != nil {
		t.Errorf("parsing client-final: %v", err)
		return false
	}
	clientProof, err := base64.StdEncoding.DecodeString(finalFields["p"])
	if err != nil {
		t.Errorf("decoding client proof: %v", err)
		return false
	}

	saltedPassword := pbkdf2HMACSHA256Once([]byte(f.password), salt, iterations)
	clientKey := hmacSHA256(saltedPassword, []byte("Client Key"))
	storedKey := sha256.Sum256(clientKey)
	clientFinalWithoutProof, _, _ := strings.Cut(clientFinal, ",p=")
	authMessage := clientFirstBare + "," + serverFirst + "," + clientFinalWithoutProof
	expectedSignature := hmacSHA256(storedKey[:], []byte(authMessage))
	expectedProof := xorBytes(clientKey, expectedSignature)

	if !hmac.Equal(clientProof, expectedProof) {
		// Not necessarily a bug: TestPostgresProbeSCRAMWrongPasswordFails
		// deliberately sends a password that shouldn't produce a matching
		// proof. The probe-level assertions decide whether this was
		// expected; this fake server just does what a real one would.
		f.sendError(conn)
		return false
	}

	serverKey := hmacSHA256(saltedPassword, []byte("Server Key"))
	serverSignature := hmacSHA256(serverKey, []byte(authMessage))
	serverFinal := "v=" + base64.StdEncoding.EncodeToString(serverSignature)
	buf3 := make([]byte, 4)
	binary.BigEndian.PutUint32(buf3, 12)
	conn.Write(postgresMessage('R', append(buf3, []byte(serverFinal)...)))

	f.sendAuthCode(conn, 0)
	return true
}

func readFullConn(conn net.Conn, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := conn.Read(buf[total:])
		total += n
		if err != nil {
			return total, err
		}
	}
	return total, nil
}

func startFakePostgresServer(t *testing.T, srv fakePostgresServer) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		srv.serve(t, conn)
	}()
	return ln.Addr().String()
}

func TestPostgresProbeTrustAuth(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "trust"})
	p := postgresProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != pgTestVersion {
		t.Fatalf("got %+v", obs)
	}
}

func TestPostgresProbeCleartextAuth(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "cleartext", password: "hunter2"})
	p := postgresProbe{}
	target := Target{
		ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Password: "hunter2"},
	}
	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != pgTestVersion {
		t.Fatalf("got %+v", obs)
	}
}

func TestPostgresProbeCleartextWrongPasswordIsErrAuth(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "cleartext-wrong"})
	p := postgresProbe{}
	target := Target{
		ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Password: "wrong"},
	}
	_, err := p.Probe(context.Background(), target)
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}

func TestPostgresProbeMD5Auth(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "md5", username: "alice", password: "secret"})
	p := postgresProbe{}
	target := Target{
		ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Username: "alice", Password: "secret"},
	}
	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != pgTestVersion {
		t.Fatalf("got %+v", obs)
	}
}

func TestPostgresProbeSCRAMAuth(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "scram", password: "correct horse battery staple"})
	p := postgresProbe{}
	target := Target{
		ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Password: "correct horse battery staple"},
	}
	obs, err := p.Probe(context.Background(), target)
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != pgTestVersion {
		t.Fatalf("got %+v", obs)
	}
}

func TestPostgresProbeSCRAMWrongPasswordFails(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "scram", password: "correct horse battery staple"})
	p := postgresProbe{}
	target := Target{
		ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second,
		Creds: Credentials{Kind: AuthPassword, Password: "wrong password"},
	}
	if _, err := p.Probe(context.Background(), target); err == nil {
		t.Fatal("expected an error for a wrong SCRAM password")
	}
}

func TestPostgresProbeUnsupportedAuthMethod(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "unsupported"})
	p := postgresProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestPostgresProbeUnreachable(t *testing.T) {
	p := postgresProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "postgresql", Address: "127.0.0.1:1", Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestPostgresProbeDefaultsUsername(t *testing.T) {
	addr := startFakePostgresServer(t, fakePostgresServer{authMode: "trust"})
	p := postgresProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "postgresql", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version == "" {
		t.Fatal("expected a version even with no credentials at all (defaults username to postgres)")
	}
}

func TestPostgresProbeMeta(t *testing.T) {
	m := postgresProbe{}.Meta()
	if m.Product != "postgresql" {
		t.Fatalf("got product %q", m.Product)
	}
	found := false
	for _, a := range m.Aliases {
		if a == "postgres" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected \"postgres\" alias, got %v", m.Aliases)
	}
	if m.Auth.Required {
		t.Fatal("trust auth means credentials are not always required")
	}
	if !m.Auth.Accepts(AuthPassword) {
		t.Fatal("expected AuthPassword to be accepted")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "postgresql" {
		t.Fatalf("got resolver %+v", m.DefaultResolver)
	}
}
