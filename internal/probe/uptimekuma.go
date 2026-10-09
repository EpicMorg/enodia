// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"
	"time"
)

// uptimeKumaProbe logs in over Uptime Kuma's own socket.io API and reads
// the version from the "info" event the server sends after login.
//
// Nothing anonymous carries it: the "info" event a fresh connection gets
// omits the version until the socket is logged in (server/client.js
// sendInfo(socket, hideVersion)), /metrics has no version series and API
// keys open only /metrics — all confirmed live on 1.23.17 and 2.5.5, and on
// a production 1.x status page. So the probe speaks just enough of
// Engine.IO v4's HTTP long-polling transport to log in: open a session,
// connect the default namespace ("40"), emit `login` with an ack
// (`420["login", {...}]`), then poll until an "info" event carrying
// "version" arrives — or the login ack says no. Real transcripts are in
// testdata/uptime-kuma_*.json. In 2.5.5 the versioned "info" can arrive
// before the ack; either order is handled.
//
// A user with 2FA can't log in this way (the ack asks for a token); that's
// reported, not worked around — use a user without 2FA for monitoring.
type uptimeKumaProbe struct{}

func (uptimeKumaProbe) Meta() Meta {
	return Meta{
		Product:       "uptime-kuma",
		Summary:       "Uptime Kuma (socket.io login)",
		DefaultScheme: "https",
		Auth:          AuthSpec{Required: true, Kinds: []AuthKind{AuthPassword}},
		// No endoflife.date page.
		DefaultResolver: ResolverRef{Type: "github", ID: "louislam/uptime-kuma"},
	}
}

const (
	engineIOPath = "/socket.io/?EIO=4&transport=polling"
	// engineIOMaxPolls bounds the polling loop; the versioned "info"
	// arrived within the third poll after login on both live versions.
	engineIOMaxPolls = 10
)

type kumaLoginAck struct {
	OK            bool   `json:"ok"`
	Msg           string `json:"msg"`
	TokenRequired bool   `json:"tokenRequired"`
}

type kumaInfo struct {
	Version       string `json:"version"`
	LatestVersion string `json:"latestVersion"`
	DBType        string `json:"dbType"`
}

func (uptimeKumaProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}

	open, err := engineIOGet(ctx, t, engineIOPath)
	if err != nil {
		return obs, err
	}
	sid, err := engineIOSessionID(open)
	if err != nil {
		return obs, err
	}
	session := engineIOPath + "&sid=" + sid
	if err := engineIOPost(ctx, t, session, "40"); err != nil {
		return obs, err
	}
	login, err := json.Marshal([]any{"login", map[string]string{
		"username": t.Creds.Username, "password": t.Creds.Password, "token": "",
	}})
	if err != nil {
		return obs, err
	}
	if err := engineIOPost(ctx, t, session, "420"+string(login)); err != nil {
		return obs, err
	}

	for range engineIOMaxPolls {
		payload, err := engineIOGet(ctx, t, session)
		if err != nil {
			return obs, err
		}
		for _, pkt := range strings.Split(payload, "\x1e") {
			switch {
			case pkt == "2": // Engine.IO ping
				if err := engineIOPost(ctx, t, session, "3"); err != nil {
					return obs, err
				}
			case strings.HasPrefix(pkt, "430"):
				var ack []kumaLoginAck
				if err := json.Unmarshal([]byte(pkt[3:]), &ack); err != nil || len(ack) == 0 {
					return obs, fmt.Errorf("%w: unreadable login ack %q", ErrUnparseable, pkt)
				}
				if !ack[0].OK {
					if ack[0].TokenRequired {
						return obs, fmt.Errorf("%w: this user has 2FA enabled; use a monitoring user without it", ErrNotSupported)
					}
					return obs, fmt.Errorf("%w: login refused: %s", ErrAuth, ack[0].Msg)
				}
			case strings.HasPrefix(pkt, "42"):
				var ev []json.RawMessage
				if json.Unmarshal([]byte(pkt[2:]), &ev) != nil || len(ev) < 2 || string(ev[0]) != `"info"` {
					continue
				}
				var info kumaInfo
				if json.Unmarshal(ev[1], &info) != nil || info.Version == "" {
					continue // the pre-login "info", without a version
				}
				_ = engineIOPost(ctx, t, session, "41") // disconnect; best effort
				obs.Version = info.Version
				obs.Endpoint = "/socket.io/"
				obs.Extra = map[string]string{}
				if info.LatestVersion != "" {
					obs.Extra["latestVersion"] = info.LatestVersion
				}
				if info.DBType != "" {
					obs.Extra["dbType"] = info.DBType
				}
				obs.DurationMS = time.Since(start).Milliseconds()
				return obs, nil
			}
		}
	}
	return obs, fmt.Errorf("%w: no versioned info event after login", ErrUnparseable)
}

// engineIOSessionID reads the sid out of the open packet, `0{"sid": ...}`.
func engineIOSessionID(open string) (string, error) {
	if !strings.HasPrefix(open, "0{") {
		return "", fmt.Errorf("%w: no Engine.IO open packet at /socket.io/ (not Uptime Kuma?)", ErrNotSupported)
	}
	var hs struct {
		SID string `json:"sid"`
	}
	if err := json.Unmarshal([]byte(open[1:]), &hs); err != nil || hs.SID == "" {
		return "", fmt.Errorf("%w: unreadable Engine.IO open packet", ErrUnparseable)
	}
	return hs.SID, nil
}

func engineIOGet(ctx context.Context, t Target, path string) (string, error) {
	resp, err := FetchHTTP(ctx, t, Request{Path: path})
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	body, err := ReadBody(resp)
	if err != nil {
		return "", err
	}
	return string(body), nil
}

func engineIOPost(ctx context.Context, t Target, path, payload string) error {
	resp, err := FetchHTTP(ctx, t, Request{
		Path: path, Method: "POST", Body: []byte(payload),
		Headers: map[string]string{"Content-Type": "text/plain;charset=UTF-8"},
	})
	if err != nil {
		return err
	}
	resp.Body.Close()
	return nil
}
