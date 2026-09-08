// SPDX-License-Identifier: AGPL-3.0-or-later

package resolver

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/EpicMorg/enodia/internal/probe"
)

// endoflifeSource fetches a product's lifecycle calendar from
// https://endoflife.date/api/<id>.json. ref.ID is the product slug the
// service uses — the same slugs already recorded as probe.Meta's
// DefaultResolver in the atlassian probes, e.g. "jira-software".
type endoflifeSource struct {
	BaseURL string // defaults to https://endoflife.date/api
	Client  *http.Client
}

func (s *endoflifeSource) Fetch(ctx context.Context, ref probe.ResolverRef) ([]Cycle, error) {
	base := s.BaseURL
	if base == "" {
		base = "https://endoflife.date/api"
	}
	client := s.Client
	if client == nil {
		client = http.DefaultClient
	}

	addr := strings.TrimSuffix(base, "/") + "/" + ref.ID + ".json"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, addr, nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	req.Header.Set("Accept", "application/json")

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

	var cycles []Cycle
	if err := json.Unmarshal(body, &cycles); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnparseable, err)
	}
	return cycles, nil
}
