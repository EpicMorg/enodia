// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"
)

// qbittorrentProbe reads qBittorrent's version from its Web UI API:
// POST /api/v2/auth/login (form fields username/password), then GET
// /api/v2/app/version with the session cookie it set ("v5.2.4"), and
// /api/v2/app/buildInfo for libtorrent/Qt into extra. Every endpoint,
// even /, answers 401 without a session — confirmed live against
// linuxserver/qbittorrent 5.2.4, where the login answered 204 and set
// QBT_SID_<port> (4.x answers 200 "Ok." and sets SID; the cookie is passed
// back whatever its name). A wrong password is 401 on 5.x and 200 "Fails."
// on 4.x. Without credentials the probe tries the version endpoint
// directly, for a Web UI that bypasses auth for the prober's subnet.
//
// qBittorrent's Web UI checks that the Host header's port matches its own
// (behind a port-mapping reverse proxy it must be told so) and that a
// Referer/Origin matches Host; the login sends the target's own origin.
type qbittorrentProbe struct{}

func (qbittorrentProbe) Meta() Meta {
	return Meta{
		Product:       "qbittorrent",
		Summary:       "qBittorrent (Web UI API)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false, Kinds: []AuthKind{AuthPassword}},
		// No endoflife.date page; GitHub releases are "release-5.2.4".
		DefaultResolver: ResolverRef{Type: "github", ID: "qbittorrent/qBittorrent"},
	}
}

var (
	qbittorrentVersionPattern = regexp.MustCompile(`^v?(\d+(?:\.\d+)+\S*)$`)
	qbittorrentLibtorrent     = regexp.MustCompile(`"libtorrent"\s*:\s*"([^"]+)"`)
	qbittorrentQt             = regexp.MustCompile(`"qt"\s*:\s*"([^"]+)"`)
)

func (qbittorrentProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	var cookie string
	if !t.Creds.IsZero() {
		c, err := qbittorrentLogin(ctx, t)
		if err != nil {
			return obs, err
		}
		cookie = c
		defer qbittorrentLogout(ctx, t, cookie)
	}

	headers := map[string]string{}
	if cookie != "" {
		headers["Cookie"] = cookie
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/api/v2/app/version", Headers: headers})
	if err != nil {
		if cookie == "" && errors.Is(err, ErrAuth) {
			return obs, fmt.Errorf("%w: the Web UI requires a login; configure credentials (kind: password)", ErrAuth)
		}
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	body, err := ReadBody(resp)
	if err != nil {
		return obs, err
	}
	m := qbittorrentVersionPattern.FindStringSubmatch(strings.TrimSpace(string(body)))
	if m == nil {
		return obs, fmt.Errorf("%w: /api/v2/app/version answered %q (not qBittorrent?)", ErrNotSupported, strings.TrimSpace(string(body)))
	}
	obs.Version = m[1]

	if bresp, err := FetchHTTP(ctx, t, Request{Path: "/api/v2/app/buildInfo", Headers: headers}); err == nil {
		if b, err := ReadBody(bresp); err == nil {
			obs.Extra = map[string]string{}
			if bm := qbittorrentLibtorrent.FindSubmatch(b); bm != nil {
				obs.Extra["libtorrent"] = string(bm[1])
			}
			if bm := qbittorrentQt.FindSubmatch(b); bm != nil {
				obs.Extra["qt"] = string(bm[1])
			}
		}
		bresp.Body.Close()
	}
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

// qbittorrentLogin logs in and returns the session cookie(s) as a Cookie
// header value.
func qbittorrentLogin(ctx context.Context, t Target) (string, error) {
	origin, err := normalizeAddress(t.Address, "https")
	if err != nil {
		return "", err
	}
	form := url.Values{"username": {t.Creds.Username}, "password": {t.Creds.Password}}
	resp, err := FetchHTTP(ctx, t, Request{
		Path: "/api/v2/auth/login", Method: http.MethodPost, Body: []byte(form.Encode()),
		Headers: map[string]string{
			"Content-Type": "application/x-www-form-urlencoded",
			"Referer":      origin.Scheme + "://" + origin.Host,
		},
	})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, _ := ReadBody(resp)
	if strings.TrimSpace(string(body)) == "Fails." {
		return "", fmt.Errorf("%w: qBittorrent refused the login", ErrAuth)
	}
	var parts []string
	for _, c := range resp.Cookies() {
		parts = append(parts, c.Name+"="+c.Value)
	}
	if len(parts) == 0 {
		return "", fmt.Errorf("%w: login set no session cookie", ErrUnparseable)
	}
	return strings.Join(parts, "; "), nil
}

func qbittorrentLogout(ctx context.Context, t Target, cookie string) {
	resp, err := FetchHTTP(ctx, t, Request{Path: "/api/v2/auth/logout", Method: http.MethodPost, Headers: map[string]string{"Cookie": cookie}})
	if err == nil {
		resp.Body.Close()
	}
}
