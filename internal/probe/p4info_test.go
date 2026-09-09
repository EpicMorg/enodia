// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// fakeP4Binary writes an executable shell script standing in for the real
// p4 CLI and returns its path. Perforce's own binary isn't assumed to be
// installed wherever these tests run — this is exactly the escape hatch
// options.binary itself exists for (see p4info.go).
func fakeP4Binary(t *testing.T, script string) string {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("fake binary is a POSIX shell script")
	}
	path := filepath.Join(t.TempDir(), "fake-p4")
	if err := os.WriteFile(path, []byte("#!/bin/sh\n"+script), 0o755); err != nil {
		t.Fatalf("writing fake p4: %v", err)
	}
	return path
}

func loadP4Fixture(t *testing.T, name string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return string(raw)
}

func p4TestTarget(binary string) Target {
	return Target{
		ID: "x", Product: "p4d", Address: "p4.example.invalid:1666",
		Options: map[string]string{p4InfoBinaryOption: binary},
		Timeout: 2 * time.Second,
	}
}

func TestRunP4InfoParsesTaggedOutput(t *testing.T) {
	fixture := loadP4Fixture(t, "p4d_2024.2.txt")
	bin := fakeP4Binary(t, "cat <<'EOF'\n"+fixture+"EOF\n")

	fields, err := runP4Info(context.Background(), p4TestTarget(bin))
	if err != nil {
		t.Fatalf("runP4Info: %v", err)
	}
	if fields["serverVersion"] != "P4D/LINUX26X86_64/2024.2/2726408 (2025/02/27)" {
		t.Fatalf("got serverVersion %q", fields["serverVersion"])
	}
	if fields["ServerID"] != "p4-example-commit" {
		t.Fatalf("got ServerID %q", fields["ServerID"])
	}
	// transportInfo's continuation lines carry no "... " prefix and must
	// not be misread as fields of their own.
	if _, ok := fields["options"]; ok {
		t.Fatalf("got %+v, want transportInfo's continuation lines skipped", fields)
	}
}

// A real p4.exe on Windows writes \r\n; splitting on \n alone leaves a
// trailing \r on every line, which must not end up inside a field's value.
func TestRunP4InfoStripsWindowsLineEndings(t *testing.T) {
	bin := fakeP4Binary(t, "printf '... serverVersion P4D/LINUX26X86_64/2024.2/2726408 (2025/02/27)\\r\\n... ServerID p4-example-commit\\r\\n'\n")

	fields, err := runP4Info(context.Background(), p4TestTarget(bin))
	if err != nil {
		t.Fatalf("runP4Info: %v", err)
	}
	if fields["ServerID"] != "p4-example-commit" {
		t.Fatalf("got ServerID %q, want no trailing \\r", fields["ServerID"])
	}
}

// A p4 process stuck dialing an unreachable direct server (no response,
// no RST — exactly what this project hit live, see D28) must not hang
// this probe forever: t.Timeout has to actually reach the subprocess,
// the same way every other probe in this tree already enforces it
// (sshexec.go, tcp.go, http.go).
func TestRunP4InfoRespectsTimeout(t *testing.T) {
	// exec, not a plain "sleep 5": the real p4 binary is a single native
	// process, not a shell wrapping a child process. A plain "sleep 5"
	// would run as a *child* of the fake script's own shell, and
	// killing the shell on timeout doesn't also kill an orphaned
	// grandchild — that's a real Go exec.CommandContext gotcha, but not
	// one the real (non-shell-wrapped) p4 binary is exposed to, so
	// asserting against it here would test the wrong thing.
	bin := fakeP4Binary(t, "exec sleep 5\n")
	target := p4TestTarget(bin)
	target.Timeout = 100 * time.Millisecond

	start := time.Now()
	_, err := runP4Info(context.Background(), target)
	elapsed := time.Since(start)

	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
	if elapsed > 2*time.Second {
		t.Fatalf("runP4Info took %s, want it killed near the 100ms timeout, not the fake binary's 5s sleep", elapsed)
	}
}

func TestRunP4InfoBinaryNotFound(t *testing.T) {
	target := p4TestTarget("definitely-not-a-real-p4-binary-xyz")
	_, err := runP4Info(context.Background(), target)
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestRunP4InfoNonZeroExitIsUnreachable(t *testing.T) {
	bin := fakeP4Binary(t, "echo 'Connect to server failed; check $P4PORT.' >&2\nexit 1\n")
	_, err := runP4Info(context.Background(), p4TestTarget(bin))
	if !errors.Is(err, ErrUnreachable) {
		t.Fatalf("got %v, want ErrUnreachable", err)
	}
}
