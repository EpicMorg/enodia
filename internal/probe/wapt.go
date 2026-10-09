// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"regexp"
	"time"
)

// waptProbe reads the WAPT server's GET /ping, which it serves without a
// session: {"msg": "WAPT Server running", "result": {"version": "1.8.2",
// "git_hash": "1.8.2.7334-2d15afd9-debian-10-amd64", "edition":
// "community", "api_version": "v3", ...}} (confirmed live on a production
// WAPT 1.8.2 server; see testdata/wapt_1.8.2_ping.json). git_hash starts
// with the full build number (1.8.2.7334), which is used as the version
// when it extends "version"; edition and api_version go into extra.
//
// No lifecycle source: WAPT has no endoflife.date page, and Tranquil IT's
// GitHub tags stopped at 1.5 — releases are published on their own site.
type waptProbe struct{}

func (waptProbe) Meta() Meta {
	return Meta{
		Product:       "wapt",
		Summary:       "WAPT server (Tranquil IT)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: false},
	}
}

type waptPing struct {
	Msg    string `json:"msg"`
	Result struct {
		Version    string `json:"version"`
		GitHash    string `json:"git_hash"`
		Edition    string `json:"edition"`
		APIVersion string `json:"api_version"`
	} `json:"result"`
}

var waptBuildPattern = regexp.MustCompile(`^(\d+(?:\.\d+)+)`)

func (waptProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{Path: "/ping", Accept: "application/json"})
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
	var p waptPing
	if err := json.Unmarshal(body, &p); err != nil || p.Result.Version == "" {
		return obs, fmt.Errorf("%w: /ping is not a WAPT server reply", ErrNotSupported)
	}

	obs.Version = p.Result.Version
	if m := waptBuildPattern.FindString(p.Result.GitHash); len(m) > len(p.Result.Version) && m[:len(p.Result.Version)] == p.Result.Version {
		obs.Version = m
	}
	obs.Extra = map[string]string{}
	for k, v := range map[string]string{"edition": p.Result.Edition, "apiVersion": p.Result.APIVersion, "gitHash": p.Result.GitHash} {
		if v != "" {
			obs.Extra[k] = v
		}
	}
	return obs, nil
}
