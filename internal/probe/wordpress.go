// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"fmt"
	"regexp"
	"time"
)

// wordpressProbe tries two anonymous surfaces, in order, and uses whichever
// one answers first:
//
//  1. The RSS feed's own `<generator>https://wordpress.org/?v=X.Y.Z</generator>`
//     line — `/?feed=rss2`, the query-string form that works regardless of
//     whether pretty permalinks are configured (confirmed live: a stock
//     wordpress:latest install without permalinks set up 404s on `/feed/`
//     but answers this form fine).
//  2. The homepage's `<meta name="generator" content="WordPress X.Y.Z" />`
//     tag — `/`.
//
// The feed is tried first because it survives the single most common
// hardening step: WordPress registers `the_generator()` on the feed hooks
// (`rss2_head`, `atom_head`, ...) separately from `wp_head`'s own
// `wp_generator` action, so the one-line `remove_action('wp_head',
// 'wp_generator')` snippet every "hide your WordPress version" tutorial
// gives only removes the homepage tag, not this one — confirmed by reading
// wp-includes/default-filters.php's actual hook registrations, not assumed.
// Sites that have gone further and disabled feeds entirely, or stripped
// both signals, fall through to ErrNotSupported.
type wordpressProbe struct{}

func (wordpressProbe) Meta() Meta {
	return Meta{
		Product:         "wordpress",
		Summary:         "WordPress",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "wordpress"},
	}
}

// wordpressFeedGeneratorPattern matches the RSS/Atom/RDF feed generator
// line. Verified against a live server's real `/?feed=rss2` reply (see
// testdata/wordpress_7.1_feed.xml).
var wordpressFeedGeneratorPattern = regexp.MustCompile(`<generator>https://wordpress\.org/\?v=([^<]+)</generator>`)

// wordpressMetaGeneratorPattern matches the homepage's own generator meta
// tag. Verified against a live server's real "/" reply (see
// testdata/wordpress_7.1_meta.html).
var wordpressMetaGeneratorPattern = regexp.MustCompile(`<meta name="generator" content="WordPress ([^"]+)"`)

func (wordpressProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	version, endpoint, err := wordpressFromFeed(ctx, t)
	if err != nil {
		version, endpoint, err = wordpressFromHomepage(ctx, t)
		if err != nil {
			return obs, err
		}
	}

	obs.Version = version
	obs.Endpoint = endpoint
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}

func wordpressFromFeed(ctx context.Context, t Target) (version, endpoint string, err error) {
	resp, err := FetchHTTP(ctx, t, Request{Path: "/?feed=rss2", Accept: "application/rss+xml"})
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := ReadBody(resp)
	if err != nil {
		return "", "", err
	}
	if m := wordpressFeedGeneratorPattern.FindSubmatch(body); m != nil {
		return string(m[1]), resp.Request.URL.Path, nil
	}
	return "", "", fmt.Errorf("%w: feed has no wordpress.org generator line", ErrNotSupported)
}

func wordpressFromHomepage(ctx context.Context, t Target) (version, endpoint string, err error) {
	resp, err := FetchHTTP(ctx, t, Request{Path: "/", Accept: "text/html"})
	if err != nil {
		return "", "", err
	}
	defer resp.Body.Close()
	body, err := ReadBody(resp)
	if err != nil {
		return "", "", err
	}
	if m := wordpressMetaGeneratorPattern.FindSubmatch(body); m != nil {
		return string(m[1]), resp.Request.URL.Path, nil
	}
	return "", "", fmt.Errorf("%w: neither the feed nor the homepage carries a WordPress version "+
		"(either this isn't WordPress, or both generator tags have been removed)", ErrNotSupported)
}
