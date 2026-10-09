// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

// The replies of a live linuxserver/qbittorrent 5.2.4, verbatim.
const (
	qbtVersion   = "v5.2.4"
	qbtBuildInfo = `{"bitness":64,"boost":"1.92.0","libtorrent":"2.0.15.0","openssl":"4.0.2","platform":"linux","qt":"6.11.2","zlib":"1.3.2"}`
)

// qbtServer mimics qBittorrent's Web UI: v5 answers the login with 204 and
// sets QBT_SID_<port> (a wrong password is 401); v4 answers 200 "Ok." and
// sets SID ("Fails." for a wrong password). Everything else needs the
// session cookie.
func qbtServer(t *testing.T, v5 bool) string {
	t.Helper()
	cookie := "SID"
	if v5 {
		cookie = "QBT_SID_8080"
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v2/auth/login":
			if r.Header.Get("Referer") == "" {
				t.Error("login sent no Referer")
			}
			if err := r.ParseForm(); err != nil || r.PostForm.Get("password") != "secret" {
				if v5 {
					http.Error(w, "Unauthorized", http.StatusUnauthorized)
				} else {
					_, _ = w.Write([]byte("Fails."))
				}
				return
			}
			http.SetCookie(w, &http.Cookie{Name: cookie, Value: "s3ss10n"})
			if v5 {
				w.WriteHeader(http.StatusNoContent)
			} else {
				_, _ = w.Write([]byte("Ok."))
			}
		case "/api/v2/auth/logout":
		default:
			if c, err := r.Cookie(cookie); err != nil || c.Value != "s3ss10n" {
				http.Error(w, "Forbidden", http.StatusForbidden)
				return
			}
			switch r.URL.Path {
			case "/api/v2/app/version":
				_, _ = w.Write([]byte(qbtVersion))
			case "/api/v2/app/buildInfo":
				_, _ = w.Write([]byte(qbtBuildInfo))
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv.URL
}

func qbtTarget(addr, password string) Target {
	tt := target(addr, "qbittorrent")
	tt.Creds = Credentials{Kind: AuthPassword, Username: "admin", Password: password}
	tt.AllowInsecureTransport = true // httptest is plain HTTP
	return tt
}

func TestQBittorrentProbeLogin(t *testing.T) {
	for _, v5 := range []bool{true, false} {
		obs, err := qbittorrentProbe{}.Probe(context.Background(), qbtTarget(qbtServer(t, v5), "secret"))
		if err != nil {
			t.Fatalf("v5=%v: Probe: %v", v5, err)
		}
		if obs.Version != "5.2.4" || obs.Extra["libtorrent"] != "2.0.15.0" || obs.Extra["qt"] != "6.11.2" {
			t.Fatalf("v5=%v: got %q %+v", v5, obs.Version, obs.Extra)
		}
	}
}

func TestQBittorrentProbeBadPasswordIsErrAuth(t *testing.T) {
	for _, v5 := range []bool{true, false} {
		if _, err := (qbittorrentProbe{}).Probe(context.Background(), qbtTarget(qbtServer(t, v5), "nope")); !errors.Is(err, ErrAuth) {
			t.Fatalf("v5=%v: got %v, want ErrAuth", v5, err)
		}
	}
}

func TestQBittorrentProbeNoCredentialsIsErrAuth(t *testing.T) {
	if _, err := (qbittorrentProbe{}).Probe(context.Background(), target(qbtServer(t, true), "qbittorrent")); !errors.Is(err, ErrAuth) {
		t.Fatalf("got %v, want ErrAuth", err)
	}
}
