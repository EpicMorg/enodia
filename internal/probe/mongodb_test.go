// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func loadMongoDBFixture(t *testing.T) []byte {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", "mongodb_7.0.40.bin"))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return raw
}

// mongoServer is a throwaway TCP listener that writes a fixed reply to
// every connection's first message, standing in for a real mongod the same
// way testdata/*.bin fixtures do for the HTTP probes' JSON bodies.
func mongoServer(t *testing.T, reply []byte) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		buf := make([]byte, 4096)
		_, _ = conn.Read(buf) // discard the request; every test sends a fixed reply regardless
		_, _ = conn.Write(reply)
	}()
	return ln.Addr().String()
}

// mongodb_7.0.40.bin is a real OP_MSG buildInfo reply captured from a live
// mongod (mongo:7) with --auth and a root user configured — confirmed the
// exact same reply comes back from an instance with no access control at
// all, since buildInfo needs no credentials either way.
func TestMongoDBProbeParsesRealFixture(t *testing.T) {
	addr := mongoServer(t, loadMongoDBFixture(t))

	p := mongodbProbe{}
	obs, err := p.Probe(context.Background(), Target{ID: "x", Product: "mongodb", Address: addr, Timeout: 2 * time.Second})
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "7.0.40" {
		t.Fatalf("got version %q", obs.Version)
	}
}

func TestMongoDBProbeWrongOpCodeIsNotSupported(t *testing.T) {
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], 16)
	binary.LittleEndian.PutUint32(header[12:16], 1) // OP_REPLY, the legacy opcode — not OP_MSG
	addr := mongoServer(t, header)

	p := mongodbProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "mongodb", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestMongoDBProbeMissingVersionField(t *testing.T) {
	// A minimal but well-formed OP_MSG reply whose document has no
	// "version" field at all — {ok: 1} at the top level.
	doc := bsonDocInt32AndString("placeholder", 1, "$db", "admin") // reuses the encoder just to get a valid doc shape
	section := append([]byte{0, 0, 0, 0, 0}, doc...)
	header := make([]byte, 16)
	binary.LittleEndian.PutUint32(header[0:4], uint32(16+len(section)))
	binary.LittleEndian.PutUint32(header[12:16], mongoOpCodeMsg)
	addr := mongoServer(t, append(header, section...))

	p := mongodbProbe{}
	_, err := p.Probe(context.Background(), Target{ID: "x", Product: "mongodb", Address: addr, Timeout: 2 * time.Second})
	if !errors.Is(err, ErrUnparseable) {
		t.Fatalf("got %v, want ErrUnparseable", err)
	}
}

func TestMongoDBProbeMeta(t *testing.T) {
	m := mongodbProbe{}.Meta()
	if m.Product != "mongodb" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("buildInfo needs no credentials, confirmed live with --auth enabled")
	}
	if m.DefaultResolver.Type != "endoflife" || m.DefaultResolver.ID != "mongodb" {
		t.Fatalf("got resolver %+v, want endoflife/mongodb", m.DefaultResolver)
	}
}

func TestBSONTopLevelStringRoundTrip(t *testing.T) {
	doc := bsonDocInt32AndString("ok", 1, "version", "7.0.40")
	version, found, err := bsonTopLevelString(doc, "version")
	if err != nil {
		t.Fatalf("bsonTopLevelString: %v", err)
	}
	if !found {
		t.Fatal("expected version to be found")
	}
	if version != "7.0.40" {
		t.Fatalf("got %q", version)
	}
}
