// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"regexp"
	"sort"
	"strconv"
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

	// Branches reports one Cycle per major.minor branch, each with its own
	// highest tag as Latest, instead of one Cycle for the single highest
	// tag. For a project maintaining several branches at once: FreeRADIUS
	// ships 3.0.x and 3.2.x releases side by side (confirmed live:
	// release_3_2_10 and release_3_0_28 among its newest tags), and a
	// fully patched 3.0.28 must read as current on its branch, with a
	// newer branch available, not as "behind 3.2.10". Registered as
	// "github-tag-branches"; pgAdmin's "github-tags" keeps the single
	// cycle, since its minor numbers are releases, not branches.
	Branches bool
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

	perPage := 30
	if s.Branches {
		perPage = 100 // GitHub's maximum: enough to reach an older branch's last tags
	}
	addr := strings.TrimSuffix(base, "/") + "/repos/" + ref.ID + "/tags?per_page=" + strconv.Itoa(perPage)
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

	if s.Branches {
		return branchCycles(tags, ref.ID)
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

// branchCycles groups tags by major.minor, newest branch first, each
// Cycle's Latest its branch's highest tag.
func branchCycles(tags []githubTag, id string) ([]Cycle, error) {
	latest := map[string]string{}
	for _, tg := range tags {
		v, ok := normalizeRELTag(tg.Name)
		if !ok {
			continue
		}
		parts := strings.SplitN(v, ".", 3)
		if len(parts) < 2 {
			continue
		}
		branch := parts[0] + "." + parts[1]
		if have, ok := latest[branch]; !ok {
			latest[branch] = v
		} else if cmp, ok := version.Compare(v, have); ok && cmp > 0 {
			latest[branch] = v
		}
	}
	if len(latest) == 0 {
		return nil, fmt.Errorf("%w: %q has no tag this resolver can parse a version from", ErrUnknownProduct, id)
	}
	out := make([]Cycle, 0, len(latest))
	for branch, v := range latest {
		out = append(out, Cycle{Cycle: branch, Latest: v})
	}
	sort.Slice(out, func(i, j int) bool {
		cmp, _ := version.Compare(out[i].Cycle, out[j].Cycle)
		return cmp > 0
	})
	return out, nil
}
