// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"
)

// rawTCPTestServer accepts exactly one connection and writes raw to it,
// then closes. Used by every raw-TCP probe's end-to-end test to replay a
// recorded fixture over a real socket instead of a bare io.Reader.
func rawTCPTestServer(t *testing.T, raw []byte) string {
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
		defer conn.Close()
		_, _ = conn.Write(raw)
	}()
	return ln.Addr().String()
}

func TestDefaultPortAppendsWhenMissing(t *testing.T) {
	if got, want := defaultPort("db.example.com", "1234"), "db.example.com:1234"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDefaultPortKeepsExplicitPort(t *testing.T) {
	if got, want := defaultPort("db.example.com:9999", "1234"), "db.example.com:9999"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDefaultPortStripsTCPScheme(t *testing.T) {
	if got, want := defaultPort("tcp://db.example.com:9999", "1234"), "db.example.com:9999"; got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDefaultPortHandlesBareIPv6(t *testing.T) {
	if got, want := defaultPort("::1", "1234"), net.JoinHostPort("::1", "1234"); got != want {
		t.Fatalf("got %q, want %q", got, want)
	}
}

func TestDialTCPUnreachableIsErrUnreachable(t *testing.T) {
	_, _, err := dialTCP(context.Background(), "127.0.0.1:1", time.Second)
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}

func TestDialTCPCancelClosesConnection(t *testing.T) {
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()

	accepted := make(chan struct{})
	go func() {
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		close(accepted)
		defer conn.Close()
		time.Sleep(2 * time.Second) // never writes anything
	}()

	ctx, cancel := context.WithCancel(context.Background())
	conn, cleanup, err := dialTCP(ctx, ln.Addr().String(), 30*time.Second)
	if err != nil {
		t.Fatalf("dialTCP: %v", err)
	}
	defer cleanup()

	<-accepted
	cancel()

	readDone := make(chan error, 1)
	go func() {
		_, err := conn.Read(make([]byte, 1))
		readDone <- err
	}()

	select {
	case err := <-readDone:
		if err == nil {
			t.Fatal("expected the read to fail once ctx was canceled")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Read did not unblock promptly after context cancellation")
	}
	if ctx.Err() == nil {
		t.Fatal("expected ctx.Err() to be non-nil after cancel")
	}
}

func TestTCPErrPrefersContextError(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got := tcpErr(ctx, errors.New("use of closed network connection"))
	if !errors.Is(got, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", got)
	}
}

func TestTCPErrPassesThroughWhenContextIsFine(t *testing.T) {
	original := errors.New("boom")
	got := tcpErr(context.Background(), original)
	if !errors.Is(got, original) {
		t.Fatalf("got %v, want the original error unchanged", got)
	}
}
