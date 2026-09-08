// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// clickhouseProbe runs `SELECT version()` against the HTTP interface (port
// 8123 by default) and reads the plain-text reply — ClickHouse's default
// output format for a single-column, single-row result is bare
// TabSeparated, so a successful query's body is just "26.8.2.7\n", nothing
// to unmarshal.
//
// Confirmed live against a real clickhouse/clickhouse-server container:
// recent images require CLICKHOUSE_PASSWORD to be set at all (no blank
// default-user password to fall back to, unlike older installs) — an
// unauthenticated request gets a normal 401, which FetchHTTP already turns
// into ErrAuth like any other probe, nothing clickhouse-specific needed.
// Whether a given deployment needs credentials depends entirely on how it
// was set up.
type clickhouseProbe struct{}

func (clickhouseProbe) Meta() Meta {
	return Meta{
		Product:         "clickhouse",
		Summary:         "ClickHouse",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "clickhouse"},
	}
}

// clickhouseVersionPattern rejects a body that isn't shaped like a version
// at all — some other HTTP service answering 200 at this address with
// unrelated content, say — rather than silently recording it as one.
// ClickHouse's own version has always been 3-5 dot-separated numbers (e.g.
// "26.8.2.7"); this is intentionally looser than exactly 4 to tolerate
// older releases without needing to pin an exact count.
var clickhouseVersionPattern = regexp.MustCompile(`^\d+(?:\.\d+){2,4}$`)

func (clickhouseProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/?query=" + url.QueryEscape("SELECT version()"),
		Accept: "text/plain",
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	body, err := ReadBody(resp)
	if err != nil {
		return obs, err
	}

	version := strings.TrimSpace(string(body))
	if !clickhouseVersionPattern.MatchString(version) {
		return obs, fmt.Errorf("%w: reply %q does not look like a ClickHouse version", ErrUnparseable, version)
	}

	obs.Version = version
	return obs, nil
}
