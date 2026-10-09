// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"html"
	"regexp"
	"time"
)

// codeServerProbe reads code-server's version from its login page,
// anonymously: the page carries <meta id="coder-options"
// data-settings="{...}"> — HTML-escaped JSON — whose codeServerVersion is
// the server's ("4.141.0"; confirmed live on codercom/code-server:latest,
// whose `code-server --version` said 4.141.0 with Code 1.141.0). /version
// needs the password; /healthz has none. `/` redirects to ./login when a
// password is set; with auth off it serves the editor, which carries the
// same meta element.
type codeServerProbe struct{}

func (codeServerProbe) Meta() Meta {
	return Meta{
		Product:         "code-server",
		Summary:         "code-server (VS Code in the browser)",
		DefaultScheme:   "https",
		Auth:            AuthSpec{Required: false},
		DefaultResolver: ResolverRef{Type: "github", ID: "coder/code-server"},
	}
}

var codeServerOptionsPattern = regexp.MustCompile(`<meta id="coder-options" data-settings="([^"]*)"`)

func (codeServerProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	resp, err := FetchHTTP(ctx, t, Request{Path: "/login", Accept: "text/html"})
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
	m := codeServerOptionsPattern.FindSubmatch(body)
	if m == nil {
		return obs, fmt.Errorf("%w: no coder-options meta on /login (not code-server?)", ErrNotSupported)
	}
	var opts struct {
		CodeServerVersion string `json:"codeServerVersion"`
	}
	if err := json.Unmarshal([]byte(html.UnescapeString(string(m[1]))), &opts); err != nil || opts.CodeServerVersion == "" {
		return obs, fmt.Errorf("%w: coder-options carries no codeServerVersion", ErrUnparseable)
	}
	obs.Version = opts.CodeServerVersion
	return obs, nil
}
