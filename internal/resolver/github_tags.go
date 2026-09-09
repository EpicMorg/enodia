// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"strings"

	"github.com/EpicMorg/enodia/internal/probe"
	"github.com/EpicMorg/enodia/internal/version"
)

// githubTagsSource is for products with no GitHub Releases at all (only git
// tags) whose tag names aren't a bare dotted version either — pgAdmin's own
// pgadmin-org/pgadmin4 tags this way ("REL-9_17"), confirmed live: its
// releases endpoint returns an empty array, and internal/version's numeric-
// spine extraction on the raw tag name would read "REL-9_17" as just "9",
// silently dropping the revision.
//
// The tags endpoint carries no dates and no draft/prerelease flags (unlike
// Releases), so every returned Cycle has ReleaseDate/LatestReleaseDate nil —
// the same "unknown, not false" reasoning githubSource already applies to
// eol/support/lts. It also has no documented ordering to rely on for
// "latest" the way Releases' reverse-chronological order lets githubSource
// just take the first eligible entry — so this fetches a page of tags and
// picks the highest-parsing version among them, rather than trusting
// position.
type githubTagsSource struct {
	BaseURL string // defaults to https://api.github.com
	Client  *http.Client
	Token   string // optional; unauthenticated requests are capped at 60/hour
}

type githubTag struct {
	Name string `json:"name"`
}

// relTagPrefix strips a tag's leading non-digit decoration ("REL-" and
// similar), leaving the digits-and-underscores spine. Applied only by
// normalizeRELTag below.
var relTagPrefix = regexp.MustCompile(`^\D+`)

// normalizeRELTag converts a "REL-9_17"-style tag into the dotted version
// ("9.17") the rest of this project already compares and displays, or
// reports ok=false for a tag with no digits at all (a "docs" or "ci" tag
// unrelated to any release, e.g.) so the caller can skip it rather than
// treat it as version "0".
func normalizeRELTag(tag string) (string, bool) {
	s := relTagPrefix.ReplaceAllString(tag, "")
	s = strings.ReplaceAll(s, "_", ".")
	core := version.Core(s)
	if core == "" {
		return "", false
	}
	return core, true
}

func (s *githubTagsSource) Fetch(ctx context.Context, ref probe.ResolverRef) ([]Cycle, error) {
	base := s.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	addr := strings.TrimSuffix(base, "/") + "/repos/" + ref.ID + "/tags?per_page=30"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if s.Token != "" {
		req.Header.Set("Authorization", "Bearer "+s.Token)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusNotFound {
		return nil, fmt.Errorf("%w: %q", ErrUnknownProduct, ref.ID)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: HTTP %d", ErrUnreachable, resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	var tags []githubTag
	if err := json.Unmarshal(body, &tags); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnparseable, err)
	}

	var best string
	for _, tg := range tags {
		v, ok := normalizeRELTag(tg.Name)
		if !ok {
			continue
		}
		if best == "" {
			best = v
			continue
		}
		if cmp, ok := version.Compare(v, best); ok && cmp > 0 {
			best = v
		}
	}
	if best == "" {
		return nil, fmt.Errorf("%w: %q has no tag this resolver can parse a version from", ErrUnknownProduct, ref.ID)
	}
	return []Cycle{{Cycle: best, Latest: best}}, nil
}
