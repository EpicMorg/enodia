// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// githubSource is the fallback for products with no lifecycle calendar: it
// reports only the latest non-draft, non-prerelease tag from GitHub
// Releases. It never knows eol/support/lts — those stay nil (unknown), not
// false, because GitHub simply has no opinion on a project's lifecycle
// policy. ref.ID is "owner/repo".
type githubSource struct {
	BaseURL string // defaults to https://api.github.com
	Client  *http.Client
	Token   string // optional; unauthenticated requests are capped at 60/hour
}

type githubRelease struct {
	TagName     string     `json:"tag_name"`
	Draft       bool       `json:"draft"`
	Prerelease  bool       `json:"prerelease"`
	PublishedAt *time.Time `json:"published_at"`
}

func (s *githubSource) Fetch(ctx context.Context, ref probe.ResolverRef) ([]Cycle, error) {
	base := s.BaseURL
	if base == "" {
		base = "https://api.github.com"
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	addr := strings.TrimSuffix(base, "/") + "/repos/" + ref.ID + "/releases?per_page=30"
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

	var releases []githubRelease
	if err := json.Unmarshal(body, &releases); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnparseable, err)
	}

	// Releases are returned newest first; the first non-draft, non-prerelease
	// entry is "latest" in the sense every other product uses that word.
	for _, rel := range releases {
		if rel.Draft || rel.Prerelease {
			continue
		}
		c := Cycle{Cycle: rel.TagName, Latest: rel.TagName}
		if rel.PublishedAt != nil {
			d := Date{Time: *rel.PublishedAt}
			c.ReleaseDate = &d
			c.LatestReleaseDate = &d
		}
		return []Cycle{c}, nil
	}
	return nil, fmt.Errorf("%w: %q has no published, non-prerelease release", ErrUnknownProduct, ref.ID)
}
