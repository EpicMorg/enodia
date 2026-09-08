// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"time"
)

// mongodbProbe runs the `buildInfo` command over the wire protocol (OP_MSG)
// and reads its "version" field. buildInfo is one of the small set of
// commands MongoDB always answers before authentication — confirmed live
// against two real mongo:7 containers, one with no access control at all
// and one with --auth and a root user configured: both returned the exact
// same full buildInfo document with no credentials sent at all. No client
// library: this hand-encodes the one BSON command document it sends and
// decodes just enough of the reply to find "version", the same level of
// protocol-level effort as mysql.go's handshake parser and redis.go's RESP
// codec.
type mongodbProbe struct{}

func (mongodbProbe) Meta() Meta {
	return Meta{
		Product: "mongodb",
		Summary: "MongoDB",
		// buildInfo needs no credentials on every deployment shape tried
		// live, auth-enabled or not — see the type comment.
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "mongodb"},
		// No DefaultScheme: a bare "host:port" address, not a URL.
	}
}

const (
	mongodbDefaultPort = "27017"
	mongoOpCodeMsg     = 2013
	maxMongoDBReply    = 4 << 20 // buildInfo's real reply is ~2KB; anything past a few MB is not this
)

func (mongodbProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, mongodbDefaultPort)
	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	if _, err := conn.Write(mongoBuildInfoRequest()); err != nil {
		return obs, tcpErr(ctx, fmt.Errorf("%w: sending buildInfo: %w", ErrUnreachable, err))
	}
	doc, err := readMongoOpMsgDocument(conn)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	version, ok, err := bsonTopLevelString(doc, "version")
	if err != nil {
		return obs, fmt.Errorf("%w: buildInfo reply: %w", ErrUnparseable, err)
	}
	if !ok {
		return obs, fmt.Errorf("%w: buildInfo reply carries no version field", ErrUnparseable)
	}

	obs.Version = version
	obs.Endpoint = addr
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// mongoBuildInfoRequest builds a complete OP_MSG wire message for
// `{buildInfo: 1, $db: "admin"}` — the smallest command every mongod
// answers pre-auth, run against "admin" because $db is mandatory in OP_MSG
// and buildInfo does not care which database it's asked from.
func mongoBuildInfoRequest() []byte {
	doc := bsonDocInt32AndString("buildInfo", 1, "$db", "admin")

	// One section, kind 0 (a plain BSON body document): flagBits (uint32,
	// always 0 here — no checksum, no more-to-come) + kind byte + the
	// document itself.
	section := make([]byte, 0, 5+len(doc))
	section = append(section, 0, 0, 0, 0) // flagBits
	section = append(section, 0)          // section kind 0
	section = append(section, doc...)

	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(section))) //nolint:gosec // a buildInfo request is ~40 bytes, nowhere near uint32's range
	binary.LittleEndian.PutUint32(header[4:8], 1)                       // requestID: any nonzero value is fine, nothing correlates it
	binary.LittleEndian.PutUint32(header[8:12], 0)                      // responseTo
	binary.LittleEndian.PutUint32(header[12:16], mongoOpCodeMsg)

	return append(header, section...)
}

// bsonDocInt32AndString encodes {<intKey>: int32(intVal), <strKey>: strVal}
// — exactly the two BSON element shapes this probe ever needs to write, in
// that field order. Not a general encoder: the generic probe's frozen
// vocabulary (docs/CLAUDE.md) is the project's stance on not growing ad hoc
// interpreters, and a full BSON writer is exactly that kind of scope creep
// for a probe that only ever sends this one fixed command.
func bsonDocInt32AndString(intKey string, intVal int32, strKey, strVal string) []byte {
	var body []byte

	body = append(body, 0x10) // int32
	body = append(body, intKey...)
	body = append(body, 0x00)
	var n [4]byte
	binary.LittleEndian.PutUint32(n[:], uint32(intVal)) //nolint:gosec // intVal is always 1 (buildInfo's own command value)
	body = append(body, n[:]...)

	body = append(body, 0x02) // string
	body = append(body, strKey...)
	body = append(body, 0x00)
	sv := append([]byte(strVal), 0x00)
	binary.LittleEndian.PutUint32(n[:], uint32(len(sv))) //nolint:gosec // strVal is "admin", nowhere near uint32's range
	body = append(body, n[:]...)
	body = append(body, sv...)

	out := make([]byte, 4)
	binary.LittleEndian.PutUint32(out, uint32(len(body)+5)) //nolint:gosec // this document is a few dozen bytes, nowhere near uint32's range
	out = append(out, body...)
	out = append(out, 0x00)
	return out
}

// readMongoOpMsgDocument reads one OP_MSG reply and returns its single
// body-kind section's BSON document, unparsed. Verified against a live
// mongod's real buildInfo reply (see testdata/mongodb_7.0.40.bin).
func readMongoOpMsgDocument(r io.Reader) ([]byte, error) {
	header := make([]byte, 16)
	if _, err := io.ReadFull(r, header); err != nil {
		return nil, fmt.Errorf("%w: reading OP_MSG header: %w", ErrUnreachable, err)
	}
	totalLen := binary.LittleEndian.Uint32(header[0:4])
	opCode := binary.LittleEndian.Uint32(header[12:16])
	if totalLen < 16 || totalLen > maxMongoDBReply {
		return nil, fmt.Errorf("%w: implausible message length %d", ErrUnparseable, totalLen)
	}
	if opCode != mongoOpCodeMsg {
		return nil, fmt.Errorf("%w: reply opCode %d is not OP_MSG (2013) — this is not a MongoDB wire protocol server", ErrNotSupported, opCode)
	}

	rest := make([]byte, totalLen-16)
	if _, err := io.ReadFull(r, rest); err != nil {
		return nil, fmt.Errorf("%w: reading OP_MSG body: %w", ErrUnreachable, err)
	}
	if len(rest) < 5 {
		return nil, fmt.Errorf("%w: OP_MSG body too short for a section", ErrUnparseable)
	}
	// flagBits (4 bytes, ignored — buildInfo's reply is always a single
	// kind-0 section, never checksummed or split) + section kind byte.
	if rest[4] != 0x00 {
		return nil, fmt.Errorf("%w: first OP_MSG section has kind %d, not 0", ErrUnparseable, rest[4])
	}
	return rest[5:], nil
}

// bsonTopLevelString scans a BSON document's top-level elements for a
// string-typed field named key, skipping every other field by its own type
// without needing a general-purpose BSON decoder — buildInfo's document has
// nested documents, arrays and nearly every scalar type, but this probe
// only ever reads one flat string field out of it.
func bsonTopLevelString(doc []byte, key string) (value string, found bool, err error) {
	if len(doc) < 5 {
		return "", false, fmt.Errorf("document too short (%d bytes)", len(doc))
	}
	i := 4 // skip the document's own int32 length prefix
	for i < len(doc) {
		kind := doc[i]
		i++
		if kind == 0x00 {
			break // end of document
		}
		nameStart := i
		for i < len(doc) && doc[i] != 0x00 {
			i++
		}
		if i >= len(doc) {
			return "", false, fmt.Errorf("unterminated element name")
		}
		name := string(doc[nameStart:i])
		i++ // skip the name's trailing NUL

		if kind == 0x02 && name == key {
			if i+4 > len(doc) {
				return "", false, fmt.Errorf("truncated string length for %q", name)
			}
			n := int(binary.LittleEndian.Uint32(doc[i : i+4]))
			start := i + 4
			if n < 1 || start+n > len(doc) {
				return "", false, fmt.Errorf("implausible string length %d for %q", n, name)
			}
			// n includes the trailing NUL BSON always writes for a string.
			return string(doc[start : start+n-1]), true, nil
		}

		skip, err := bsonValueLen(kind, doc[i:])
		if err != nil {
			return "", false, fmt.Errorf("skipping field %q: %w", name, err)
		}
		i += skip
	}
	return "", false, nil
}

// bsonValueLen reports how many bytes the value following a BSON type byte
// occupies, for every type buildInfo's real reply was seen to use (double,
// string, embedded document, array, binary, boolean, UTC datetime, null,
// int32, int64) plus the handful of others the BSON spec defines, so an
// unexpected-but-valid field never derails the scan of the ones this probe
// actually wants.
func bsonValueLen(kind byte, v []byte) (int, error) {
	need := func(n int) error {
		if len(v) < n {
			return fmt.Errorf("truncated value (need %d bytes, have %d)", n, len(v))
		}
		return nil
	}
	switch kind {
	case 0x01, 0x09, 0x11, 0x12: // double, UTC datetime, timestamp, int64
		return 8, need(8)
	case 0x02, 0x0D, 0x0E: // string, JavaScript code, symbol (deprecated)
		if err := need(4); err != nil {
			return 0, err
		}
		n := int(binary.LittleEndian.Uint32(v))
		return 4 + n, need(4 + n)
	case 0x03, 0x04: // embedded document, array
		if err := need(4); err != nil {
			return 0, err
		}
		n := int(binary.LittleEndian.Uint32(v))
		return n, need(n)
	case 0x05: // binary
		if err := need(5); err != nil {
			return 0, err
		}
		n := int(binary.LittleEndian.Uint32(v))
		return 5 + n, need(5 + n)
	case 0x06, 0x0A, 0xFF, 0x7F: // undefined, null, minkey, maxkey (deprecated/no payload)
		return 0, nil
	case 0x07: // ObjectId
		return 12, need(12)
	case 0x08: // boolean
		return 1, need(1)
	case 0x10: // int32
		return 4, need(4)
	case 0x13: // decimal128
		return 16, need(16)
	default:
		return 0, fmt.Errorf("unsupported BSON type %#x", kind)
	}
}
