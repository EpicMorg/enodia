// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"
)

// mariadbProbe reads the version out of MariaDB's initial handshake packet
// — the same Protocol::HandshakeV10 mysqlProbe reads (see
// readMySQLProtocolVersion in mysql.go) — but accepts exactly the replies
// mysqlProbe rejects as "not MySQL" (D9): MariaDB 10.x's "5.5.5-"-masked
// version and 11.0+'s unmasked "-MariaDB"-tagged one (see
// mariadbServerVersion). The other half of that pair, not a new transport.
type mariadbProbe struct{}

func (mariadbProbe) Meta() Meta {
	return Meta{
		Product: "mariadb",
		Summary: "MariaDB Server",
		// The handshake is read before any authentication step, so no
		// credential is ever required to observe the version.
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "mariadb"},
		// No DefaultScheme: a bare "host:port" is the address, not a URL —
		// there is no scheme to be missing (D10, same as mysql).
	}
}

// mariadbVersionPattern extracts the numeric spine from the unmasked
// version ("10.11.19" out of "10.11.19-MariaDB-ubu2204") — confirmed live
// against a real MariaDB 10.11 server (see testdata/mariadb_10.11.19.bin).
// internal/version.Core would work here too, but MariaDB's own trailing
// "-MariaDB-<os tag>" isn't one of Clean's recognised suffixes, so doing
// it explicitly here keeps the raw vendor tag available in Extra instead
// of silently discarding it.
var mariadbVersionPattern = regexp.MustCompile(`^(\d+(?:\.\d+)*)(-.*)?$`)

func (mariadbProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product, CollectedAt: start.UTC()}

	addr := defaultPort(t.Address, mysqlDefaultPort)

	conn, cleanup, err := dialTCP(ctx, addr, t.Timeout)
	if err != nil {
		return obs, err
	}
	defer cleanup()

	raw, err := readMySQLProtocolVersion(conn)
	if err != nil {
		return obs, tcpErr(ctx, err)
	}

	unmasked, ok := mariadbServerVersion(raw)
	if !ok {
		return obs, fmt.Errorf("%w: %q is neither \"5.5.5-\"-masked nor \"-MariaDB\"-tagged — this looks like MySQL, not MariaDB", ErrNotSupported, raw)
	}

	m := mariadbVersionPattern.FindStringSubmatch(unmasked)
	if m == nil {
		return obs, fmt.Errorf("%w: version %q has no recognizable numeric spine", ErrUnparseable, unmasked)
	}

	obs.Version = m[1]
	obs.Endpoint = addr
	if tag := strings.TrimPrefix(m[2], "-"); tag != "" {
		obs.Extra = map[string]string{"tag": tag}
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
