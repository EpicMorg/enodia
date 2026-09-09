// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"bytes"
	"context"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
)

// p4InfoBinaryOption is the Target.Options key naming the p4 CLI binary to
// run — "p4" (resolved via $PATH) unless overridden.
const p4InfoBinaryOption = "binary"

// p4TaggedFieldPattern matches one "... key value" line from `p4 -Ztag
// ... info`'s output. Confirmed live: some fields (transportInfo) continue
// onto further lines with no "... " prefix at all — this pattern simply
// never matches those, so they're silently skipped, which is fine since
// nothing here reads them.
var p4TaggedFieldPattern = regexp.MustCompile(`^\.\.\. (\S+) (.*)$`)

// runP4Info execs the operator's own p4 CLI against t.Address and parses
// its `-Ztag info` output into a flat key/value map.
//
// This is the one probe in this tree that shells out to an external binary
// rather than speaking a wire protocol directly (D10's usual rule). See
// docs/DECISIONS.md D28 for why: a hand-rolled minimal client for
// Perforce's own RPC protocol was fully reverse-engineered and confirmed
// working end-to-end against a real p4p proxy, but real direct p4d servers
// silently drop that exact same, byte-verified-correct handshake — TLS
// gets an immediate reset rather than a timeout, ruling out "needs
// encryption," and the behavior is consistent across two different direct
// servers with very different usage histories, ruling out a rate limit.
// Something at the network layer in front of direct p4d ports treats a
// hand-rolled client differently from the real one; the real `p4` binary
// has no such problem, so this probe uses it instead of chasing that
// further.
func runP4Info(ctx context.Context, t Target) (map[string]string, error) {
	bin := t.Options[p4InfoBinaryOption]
	if bin == "" {
		bin = "p4"
	}
	path, err := exec.LookPath(bin)
	if err != nil {
		return nil, fmt.Errorf("%w: p4 CLI %q not found (install Perforce's p4 binary, or set options.binary to its path): %w",
			ErrNotSupported, bin, err)
	}

	addr := defaultPort(t.Address, "1666")
	cmd := exec.CommandContext(ctx, path, "-Ztag", "-p", addr, "info")
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	runErr := cmd.Run()
	if ctx.Err() != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, ctx.Err())
	}
	if runErr != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = runErr.Error()
		}
		return nil, fmt.Errorf("%w: %s", ErrUnreachable, msg)
	}

	fields := make(map[string]string)
	for _, line := range strings.Split(stdout.String(), "\n") {
		m := p4TaggedFieldPattern.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		fields[m[1]] = m[2]
	}
	return fields, nil
}
