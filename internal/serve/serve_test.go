// SPDX-License-Identifier: AGPL-3.0-or-later

package serve

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/evaluate"
	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/render"
)

func getReportJSON(t *testing.T, addr string) (*http.Response, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodGet, "http://"+addr+"/report.json", nil)
	if err != nil {
		t.Fatal(err)
	}
	return http.DefaultClient.Do(req)
}

func freeAddr(t *testing.T) string {
	t.Helper()
	ln, err := new(net.ListenConfig).Listen(context.Background(), "tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

func waitForServer(t *testing.T, addr string) {
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
	t.Fatalf("server at %s never came up", addr)
}

func sampleReport(id string) render.Report {
	return render.Report{
		GeneratedAt: time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		AsOf:        time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC),
		Observations: []probe.Observation{
			{ID: id, Product: "generic", Version: "1.0", Normalized: "1.0"},
		},
		Assessments: []evaluate.Assessment{
			{ID: id, Product: "generic", Patch: evaluate.PatchCurrent},
		},
	}
}

func TestRunFailsFastOnInitialCollectionError(t *testing.T) {
	collector := func(context.Context) (render.Report, error) {
		return render.Report{}, errors.New("config is broken")
	}
	err := Run(context.Background(), collector, Options{Addr: freeAddr(t), Interval: time.Hour})
	if err == nil || !strings.Contains(err.Error(), "config is broken") {
		t.Fatalf("got %v, want an error mentioning the initial failure", err)
	}
}

func TestRunRejectsNonPositiveInterval(t *testing.T) {
	collector := func(context.Context) (render.Report, error) { return render.Report{}, nil }
	err := Run(context.Background(), collector, Options{Addr: freeAddr(t), Interval: 0})
	if err == nil {
		t.Fatal("expected an error for a zero interval")
	}
}

func TestRunServesInitialSnapshotImmediately(t *testing.T) {
	addr := freeAddr(t)
	collector := func(context.Context) (render.Report, error) { return sampleReport("first"), nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, collector, Options{Addr: addr, Interval: time.Hour}) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServer(t, addr)

	resp, err := getReportJSON(t, addr)
	if err != nil {
		t.Fatalf("GET /report.json: %v", err)
	}
	defer resp.Body.Close()
	body, _ := io.ReadAll(resp.Body)
	if !strings.Contains(string(body), `"first"`) {
		t.Fatalf("got %s, want it to mention the initial snapshot", body)
	}
}

func TestRunRefreshesOnTickerAndKeepsServing(t *testing.T) {
	addr := freeAddr(t)
	var calls atomic.Int32
	collector := func(context.Context) (render.Report, error) {
		n := calls.Add(1)
		return sampleReport(fmt.Sprintf("cycle-%d", n)), nil
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, collector, Options{Addr: addr, Interval: 20 * time.Millisecond}) }()
	defer func() {
		cancel()
		<-done
	}()

	waitForServer(t, addr)

	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		resp, err := getReportJSON(t, addr)
		if err == nil {
			body, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			if strings.Contains(string(body), `"cycle-2"`) {
				return
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("snapshot was never refreshed by the ticker")
}

func TestRunKeepsPreviousSnapshotWhenACycleFails(t *testing.T) {
	addr := freeAddr(t)
	var calls atomic.Int32
	var warnings atomic.Int32
	collector := func(context.Context) (render.Report, error) {
		n := calls.Add(1)
		if n == 1 {
			return sampleReport("good"), nil
		}
		return render.Report{}, errors.New("transient failure")
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- Run(ctx, collector, Options{
			Addr: addr, Interval: 20 * time.Millisecond,
			Warn: func(string) { warnings.Add(1) },
		})
	}()
	defer func() {
		cancel()
		<-done
	}()

	waitForServer(t, addr)
	time.Sleep(150 * time.Millisecond) // let several failing ticks pass

	resp, err := getReportJSON(t, addr)
	if err != nil {
		t.Fatalf("GET /report.json: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), `"good"`) {
		t.Fatalf("got %s, want the last good snapshot to still be served", body)
	}
	if warnings.Load() == 0 {
		t.Fatal("expected at least one warning about a failed refresh cycle")
	}
}

func TestRunShutsDownGracefullyOnContextCancel(t *testing.T) {
	addr := freeAddr(t)
	collector := func(context.Context) (render.Report, error) { return sampleReport("x"), nil }

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- Run(ctx, collector, Options{Addr: addr, Interval: time.Hour}) }()
	waitForServer(t, addr)

	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatalf("Run returned %v, want nil on a clean shutdown", err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("Run did not return promptly after context cancellation")
	}
}
