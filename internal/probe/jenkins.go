// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"time"
)

// jenkinsProbe reads the "X-Jenkins" response header, which Jenkins sets on
// every response — including a 403 to an unauthenticated request — rather
// than the response body, which never carries the version at all.
//
// Confirmed live against a jenkins/jenkins:lts-jdk17 container: a fresh
// instance with its default security realm answers /api/json 403 to an
// anonymous request, yet still sets "X-Jenkins: 2.541.3" on that same 403;
// the 200 body an authenticated request gets back (hudson.model.Hudson)
// has no version field anywhere in it. So OKStatuses must include 403 —
// it is not a failure here, just the anonymous-read-denied case — and the
// header, not the body, is what this probe actually parses.
type jenkinsProbe struct{}

func (jenkinsProbe) Meta() Meta {
	return Meta{
		Product:         "jenkins",
		Summary:         "Jenkins",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false, Kinds: []AuthKind{AuthBasic}},
		DefaultResolver: ResolverRef{Type: "endoflife", ID: "jenkins"},
	}
}

// jenkinsInfo is the subset of /api/json this probe reads when a request is
// authenticated enough to get a body at all (a 403 carries none). Verified
// against a live server's real JSON reply (see testdata/jenkins_2.541.3.json).
type jenkinsInfo struct {
	Mode        string `json:"mode"`
	UseSecurity bool   `json:"useSecurity"`
}

func (jenkinsProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Path:       "/api/json",
		Accept:     "application/json",
		OKStatuses: []int{403},
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	version := resp.Header.Get("X-Jenkins")
	if version == "" {
		return obs, fmt.Errorf("%w: no X-Jenkins response header", ErrUnparseable)
	}
	obs.Version = version

	// A 403 body is an HTML redirect to /login, not JSON — only try to read
	// the extra fields when the request actually got past authorization.
	if resp.StatusCode == http.StatusOK {
		body, err := ReadBody(resp)
		if err != nil {
			return obs, err
		}
		var info jenkinsInfo
		if err := json.Unmarshal(body, &info); err == nil {
			obs.Extra = map[string]string{}
			if info.Mode != "" {
				obs.Extra["mode"] = info.Mode
			}
			obs.Extra["useSecurity"] = fmt.Sprintf("%t", info.UseSecurity)
		}
	}
	return obs, nil
}
