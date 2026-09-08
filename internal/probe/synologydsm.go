// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"regexp"
	"time"
)

// synologyDSMProbe reads Synology DSM's version via its own Web API
// (SYNO.API.Auth to log in, then SYNO.DSM.Info for the version).
//
// This is the one HTTP probe in this tree that needs a real login step
// rather than a static credential (API token/basic/bearer): confirmed live
// that SYNO.DSM.Info always answers {"error":{"code":119}} ("no session")
// without both a session id (_sid) and, when the target has CSRF protection
// enabled (this project's own test devices did), a SynoToken — neither is
// obtainable without calling SYNO.API.Auth's login method with a real
// account and password first. This was accepted despite D22's rejection of
// exactly this shape for Redmine because it is genuinely lighter than that
// case: a plain JSON API taking username/password as normal parameters and
// returning the session id as a normal JSON field — no HTML page to scrape
// for a CSRF token, no cookie jar, just two ordinary request/response
// round trips. A best-effort logout follows the version read so collection
// doesn't accumulate open sessions on the NAS run after run.
//
// No DefaultResolver: endoflife.date has no calendar for DSM (confirmed
// 404 under synology-dsm/synology/dsm).
type synologyDSMProbe struct{}

func (synologyDSMProbe) Meta() Meta {
	return Meta{
		Product:       "synology-dsm",
		Summary:       "Synology DSM",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword}},
	}
}

// synoResponse is the envelope every Synology Web API call replies with —
// confirmed live: success:false replies carry an HTTP 200, never a 401/403,
// so auth failures must be read from this body, not the status code.
type synoResponse struct {
	Success bool            `json:"success"`
	Data    json.RawMessage `json:"data"`
	Error   struct {
		Code int `json:"code"`
	} `json:"error"`
}

type synoAuthData struct {
	Sid       string `json:"sid"`
	SynoToken string `json:"synotoken"`
}

// synoDSMInfo is the subset of SYNO.DSM.Info this probe needs. Verified
// against a live DSM 7.3.2 reply (see testdata/synology-dsm_7.3.2-86009.json).
type synoDSMInfo struct {
	VersionString string `json:"version_string"`
}

// synologyVersionPattern matches SYNO.DSM.Info's own "DSM <version>
// Update <n>" shape, confirmed live: "DSM 7.3.2-86009 Update 4".
var synologyVersionPattern = regexp.MustCompile(`^DSM (\S+)`)

func synoCall(ctx context.Context, t Target, params url.Values) (synoResponse, error) {
	var out synoResponse
	resp, err := FetchHTTP(ctx, t, Request{
		Path:   "/webapi/entry.cgi?" + params.Encode(),
		Accept: "application/json",
	})
	if err != nil {
		return out, err
	}
	defer resp.Body.Close()

	body, err := ReadBody(resp)
	if err != nil {
		return out, err
	}
	if err := json.Unmarshal(body, &out); err != nil {
		return out, fmt.Errorf("%w: parsing %s reply: %w", ErrUnparseable, params.Get("api"), err)
	}
	return out, nil
}

func (synologyDSMProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	if t.Creds.Username == "" || t.Creds.Password == "" {
		return obs, fmt.Errorf("%w: synology-dsm needs a username and password", ErrAuth)
	}

	login, err := synoCall(ctx, t, url.Values{
		"api":               {"SYNO.API.Auth"},
		"version":           {"6"},
		"method":            {"login"},
		"account":           {t.Creds.Username},
		"passwd":            {t.Creds.Password},
		"enable_syno_token": {"yes"},
	})
	if err != nil {
		return obs, err
	}
	if !login.Success {
		return obs, fmt.Errorf("%w: SYNO.API.Auth login failed (error code %d)", ErrAuth, login.Error.Code)
	}
	var auth synoAuthData
	if err := json.Unmarshal(login.Data, &auth); err != nil || auth.Sid == "" {
		return obs, fmt.Errorf("%w: login reply has no sid", ErrUnparseable)
	}
	defer func() {
		_, _ = synoCall(ctx, t, url.Values{
			"api": {"SYNO.API.Auth"}, "version": {"6"}, "method": {"logout"}, "_sid": {auth.Sid},
		})
	}()

	info, err := synoCall(ctx, t, url.Values{
		"api": {"SYNO.DSM.Info"}, "version": {"2"}, "method": {"getinfo"},
		"_sid": {auth.Sid}, "SynoToken": {auth.SynoToken},
	})
	if err != nil {
		return obs, err
	}
	if !info.Success {
		return obs, fmt.Errorf("%w: SYNO.DSM.Info failed (error code %d)", ErrUnreachable, info.Error.Code)
	}
	var dsm synoDSMInfo
	if err := json.Unmarshal(info.Data, &dsm); err != nil {
		return obs, fmt.Errorf("%w: parsing SYNO.DSM.Info data: %w", ErrUnparseable, err)
	}

	m := synologyVersionPattern.FindStringSubmatch(dsm.VersionString)
	if m == nil {
		return obs, fmt.Errorf("%w: version_string %q doesn't start with \"DSM \"", ErrUnparseable, dsm.VersionString)
	}

	obs.Version = m[1]
	obs.Endpoint = "/webapi/entry.cgi (SYNO.DSM.Info)"
	obs.DurationMS = time.Since(start).Milliseconds()
	return obs, nil
}
