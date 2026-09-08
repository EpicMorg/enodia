// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/spf13/cobra"
)

// serveTestCmd is testCmd, but with a cancellable context: runServeCmd
// blocks until it's canceled, so the plain background-context testCmd
// cannot be used to test it.
func serveTestCmd(t *testing.T) (cmd *cobra.Command, cancel context.CancelFunc) {
	t.Helper()
	cmd = &cobra.Command{}
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	ctx, cancel := context.WithCancel(context.Background())
	cmd.SetContext(ctx)
	return cmd, cancel
}

func freeListenAddr(t *testing.T) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForListener(t *testing.T, addr string) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		conn, err := new(net.Dialer).DialContext(context.Background(), "tcp", addr)
		if err == nil {
			conn.Close()
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("nothing listening on %s", addr)
}

func TestRunServeCmdServesASnapshot(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "enodia.yaml")
	writeFile(t, path, `
schemaVersion: 1
targets:
  - id: a
    product: generic
    address: https://a.example.invalid
`)
	withConfigFlag(t, path)
	withFakeResolver(t, fakeSource{})

	addr := freeListenAddr(t)
	prevListen, prevInterval := serveListenFlag, serveIntervalFlag
	serveListenFlag, serveIntervalFlag = addr, time.Hour
	t.Cleanup(func() { serveListenFlag, serveIntervalFlag = prevListen, prevInterval })

	cmd, cancel := serveTestCmd(t)
	done := make(chan error, 1)
	go func() { done <- runServeCmd(cmd, nil) }()
	t.Cleanup(func() {
		cancel()
		<-done
	})

	waitForListener(t, addr)

	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/report.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET /report.json: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"id": "a"`) {
		t.Fatalf("got %s, want it to mention target \"a\"", body)
	}
}

func TestRunServeCmdFailsFastOnMissingConfig(t *testing.T) {
	withConfigFlag(t, filepath.Join(t.TempDir(), "nope.yaml"))

	prevListen, prevInterval := serveListenFlag, serveIntervalFlag
	serveListenFlag, serveIntervalFlag = freeListenAddr(t), time.Hour
	t.Cleanup(func() { serveListenFlag, serveIntervalFlag = prevListen, prevInterval })

	cmd, cancel := serveTestCmd(t)
	defer cancel()

	err := runServeCmd(cmd, nil)
	var ee *ExitError
	if !errors.As(err, &ee) || ee.Code != 1 {
		t.Fatalf("got %v, want ExitError{Code:1}", err)
	}
}

func TestServeCmdFlagDefaults(t *testing.T) {
	if got := serveCmd.Flags().Lookup("listen").DefValue; got != ":8080" {
		t.Errorf("got --listen default %q, want :8080", got)
	}
	if got := serveCmd.Flags().Lookup("interval").DefValue; got != "1h0m0s" {
		t.Errorf("got --interval default %q, want 1h0m0s", got)
	}
}
