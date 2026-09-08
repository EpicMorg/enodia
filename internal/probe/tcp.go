// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"net"
	"strings"
	"time"
)

// defaultTCPReadTimeout is the last-resort deadline for a non-HTTP probe
// when Target.Timeout is unset.
const defaultTCPReadTimeout = 10 * time.Second

// dialTCP opens a raw TCP connection for a non-HTTP probe (D10: transport
// belongs to the probe) and arranges for ctx cancellation to close it
// immediately.
//
// DialContext only covers the dial itself; a blocking Read or Write
// afterwards does not observe ctx cancellation on its own, which matters
// because cmd/enodia wires SIGINT/SIGTERM into its root context specifically
// so a ctrl-C cancels in-flight probes rather than waiting out their
// timeouts. The returned cleanup stops that goroutine and closes the
// connection; callers must defer it before using the connection.
func dialTCP(ctx context.Context, addr string, timeout time.Duration) (conn net.Conn, cleanup func(), err error) {
	var d net.Dialer
	conn, err = d.DialContext(ctx, "tcp", addr)
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	if timeout <= 0 {
		timeout = defaultTCPReadTimeout
	}
	_ = conn.SetDeadline(time.Now().Add(timeout))

	done := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			conn.Close()
		case <-done:
		}
	}()

	return conn, func() {
		close(done)
		conn.Close()
	}, nil
}

// tcpErr prefers ctx's own error over a raw connection error: once ctx is
// canceled, dialTCP's goroutine closes the connection out from under
// whatever was reading it, and "use of closed network connection" is a far
// less useful message than what actually happened.
func tcpErr(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return fmt.Errorf("%w: %w", ErrUnreachable, ctx.Err())
	}
	return err
}

// defaultPort appends port if addr does not already carry one, and strips a
// "tcp://" prefix some users write out of HTTP-target habit even though raw
// TCP addresses have no scheme.
func defaultPort(addr, port string) string {
	addr = strings.TrimPrefix(addr, "tcp://")
	if _, _, err := net.SplitHostPort(addr); err != nil {
		return net.JoinHostPort(addr, port)
	}
	return addr
}
