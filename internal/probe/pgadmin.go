// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"time"
)

// pgadminProbe decodes the version out of the `?ver=NNNNN` cache-busting
// query string pgAdmin appends to every static asset on its own login
// page — anonymous by design, since it has to render before any session
// exists.
//
// Confirmed against a real dpage/pgadmin4 container, both the live page
// and its own source (version.py): NNNNN is APP_VERSION_INT, documented
// there as "[X]XYYZZ, where X is the release version, Y is the revision
// ... Z represents the suffix" — e.g. 91700 for release 9, revision 17,
// suffix 00 (GA). This probe only reconstructs the release.revision
// spine; a nonzero suffix code (a beta/dev build) has no documented
// text mapping to reconstruct from the code alone, so it's surfaced in
// Extra rather than guessed at.
type pgadminProbe struct{}

func (pgadminProbe) Meta() Meta {
	return Meta{
		Product:       "pgadmin",
		Summary:       "pgAdmin",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
		// endoflife.date has no pgadmin calendar (confirmed 404), and
		// pgadmin-org/pgadmin4 has no GitHub Releases at all (confirmed:
		// the releases endpoint returns an empty array) — only tags, shaped
		// "REL-9_17" rather than a dotted version. resolver.githubTagsSource
		// (Type: "github-tags") exists specifically for this: it converts
		// that shape to "9.17" and picks the highest-parsing tag from the
		// fetched page rather than trusting list order, since the tags
		// endpoint documents none.
		DefaultResolver: ResolverRef{Type: "github-tags", ID: "pgadmin-org/pgadmin4"},
	}
}

// pgadminVersionIntPattern matches the ver= cache-busting param on any
// static asset URL on the login page. Verified against a live server's
// real "/login" reply (see testdata/pgadmin_9.17.html).
var pgadminVersionIntPattern = regexp.MustCompile(`\?ver=(\d+)"`)

func (pgadminProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/login",
		Accept: "text/html",
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

	m := pgadminVersionIntPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no \"?ver=\" cache-busting param found on \"/login\" "+
			"(either this isn't pgAdmin, or its static-asset layout changed)", ErrNotSupported)
	}

	verInt, err := strconv.Atoi(string(m[1]))
	if err != nil {
		return obs, fmt.Errorf("%w: \"?ver=%s\" is not a number", ErrUnparseable, m[1])
	}

	release, revision, suffix := verInt/10000, (verInt/100)%100, verInt%100
	obs.Version = fmt.Sprintf("%d.%d", release, revision)
	if suffix != 0 {
		obs.Extra = map[string]string{"suffixCode": strconv.Itoa(suffix)}
	}
	return obs, nil
}
