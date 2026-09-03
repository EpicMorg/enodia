// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"
)

// maxBody caps how much of a response is read. Version endpoints are tiny;
// anything larger is either the wrong endpoint or someone being hostile.
const maxBody = 1 << 20 // 1 MiB

// Request is what an HTTP probe asks FetchHTTP to perform.
type Request struct {
	Path       string
	Method     string // defaults to GET
	Accept     string
	Headers    map[string]string
	OKStatuses []int // statuses that are not failures (Jenkins answers on 403)
}

// FetchHTTP performs one request against t.Address, applying credentials, and
// maps transport and status failures onto the sentinel errors.
//
// The caller must close the returned body.
func FetchHTTP(ctx context.Context, t Target, r Request) (*http.Response, error) {
	base, err := normalizeAddress(t.Address, "https")
	if err != nil {
		return nil, err
	}

	// Never put a credential on the wire in the clear without consent.
	if base.Scheme == "http" && !t.Creds.IsZero() && !t.AllowInsecureTransport {
		return nil, fmt.Errorf("%w: %s is plain HTTP; set allow_insecure_transport if you accept this", ErrInsecure, base.Host)
	}

	path := r.Path
	if t.Path != "" {
		path = t.Path
	}
	u := *base
	u.Path = strings.TrimSuffix(u.Path, "/") + path
	if i := strings.IndexByte(path, '?'); i >= 0 {
		u.Path = strings.TrimSuffix(base.Path, "/") + path[:i]
		u.RawQuery = path[i+1:]
	}

	method := r.Method
	if t.Method != "" {
		method = t.Method
	}
	if method == "" {
		method = http.MethodGet
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	if r.Accept != "" {
		req.Header.Set("Accept", r.Accept)
	}
	for k, v := range r.Headers {
		req.Header.Set(k, v)
	}
	for k, v := range t.Headers {
		req.Header.Set(k, v)
	}
	applyCredentials(req, t.Creds)

	client := t.HTTP
	if client == nil {
		client = http.DefaultClient
	}

	resp, err := client.Do(req)
	if err != nil {
		// Redact: url.Error stringifies the full URL, which is fine, but the
		// wrapped error may carry TLS detail we still want.
		var ue *url.Error
		if errors.As(err, &ue) && ue.Timeout() {
			return nil, fmt.Errorf("%w: timeout after %s", ErrUnreachable, t.Timeout)
		}
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}

	if resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden {
		if !containsInt(r.OKStatuses, resp.StatusCode) {
			resp.Body.Close()
			return nil, fmt.Errorf("%w: HTTP %d", ErrAuth, resp.StatusCode)
		}
	}
	if resp.StatusCode >= 400 && !containsInt(r.OKStatuses, resp.StatusCode) {
		resp.Body.Close()
		if resp.StatusCode == http.StatusNotFound {
			return nil, fmt.Errorf("%w: HTTP 404 at %s", ErrNotSupported, u.Path)
		}
		return nil, fmt.Errorf("%w: HTTP %d", ErrUnreachable, resp.StatusCode)
	}
	return resp, nil
}

// ReadBody reads a capped response body.
func ReadBody(resp *http.Response) ([]byte, error) {
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("%w: %w", ErrUnreachable, err)
	}
	return b, nil
}

func applyCredentials(req *http.Request, c Credentials) {
	switch c.Kind {
	case AuthBearer:
		if c.Value != "" {
			req.Header.Set("Authorization", "Bearer "+c.Value)
		}
	case AuthTokenHeader:
		h := c.Header
		if h == "" {
			h = "Authorization"
		}
		if c.Value != "" {
			req.Header.Set(h, c.Value)
		}
	case AuthBasic:
		if c.Username != "" || c.Password != "" {
			req.SetBasicAuth(c.Username, c.Password)
		}
	}
}

func containsInt(xs []int, v int) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}

// normalizeAddress parses a user-written address, defaulting the scheme.
// A missing scheme is the caller's problem to warn about; here we just resolve.
func normalizeAddress(addr, defScheme string) (*url.URL, error) {
	addr = strings.TrimSpace(addr)
	if addr == "" {
		return nil, fmt.Errorf("%w: empty address", ErrUnreachable)
	}
	if !strings.Contains(addr, "://") {
		addr = defScheme + "://" + addr
	}
	u, err := url.Parse(addr)
	if err != nil {
		return nil, fmt.Errorf("%w: bad address %q: %w", ErrUnreachable, addr, err)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: address %q has no host", ErrUnreachable, addr)
	}
	return u, nil
}

// HasScheme reports whether the user wrote an explicit scheme.
func HasScheme(addr string) bool { return strings.Contains(addr, "://") }

// NewHTTPClient builds a client for one target's TLS settings.
func NewHTTPClient(s TLSSettings, timeout time.Duration) (*http.Client, error) {
	cfg := &tls.Config{
		InsecureSkipVerify: s.Insecure, //nolint:gosec // opt-in, warned about, and recorded in the report
		ServerName:         s.ServerName,
	}
	switch s.MinVersion {
	case "1.0":
		cfg.MinVersion = tls.VersionTLS10
	case "1.1":
		cfg.MinVersion = tls.VersionTLS11
	case "1.3":
		cfg.MinVersion = tls.VersionTLS13
	default:
		cfg.MinVersion = tls.VersionTLS12
	}

	if s.CAFile != "" {
		pem, err := os.ReadFile(s.CAFile)
		if err != nil {
			return nil, fmt.Errorf("reading ca_file: %w", err)
		}
		pool, err := x509.SystemCertPool()
		if err != nil || pool == nil {
			pool = x509.NewCertPool()
		}
		if !pool.AppendCertsFromPEM(pem) {
			return nil, fmt.Errorf("ca_file %s contains no usable certificates", s.CAFile)
		}
		cfg.RootCAs = pool
	}

	if len(s.PinSHA256) > 0 {
		want := make(map[string]bool, len(s.PinSHA256))
		for _, p := range s.PinSHA256 {
			want[strings.ToLower(strings.ReplaceAll(p, ":", ""))] = true
		}
		// Pinning replaces chain verification: we trust this exact leaf.
		//
		// VerifyConnection, not VerifyPeerCertificate: the latter is skipped
		// on a resumed TLS session, which would let a pinned connection skip
		// the pin check after the first handshake. VerifyConnection runs on
		// every connection, resumed or not.
		cfg.InsecureSkipVerify = true //nolint:gosec // superseded by the pin check below
		cfg.VerifyConnection = func(cs tls.ConnectionState) error {
			for _, cert := range cs.PeerCertificates {
				sum := sha256.Sum256(cert.Raw)
				if want[hex.EncodeToString(sum[:])] {
					return nil
				}
			}
			return errors.New("no certificate in the chain matched the configured pin")
		}
	}

	tr := &http.Transport{
		TLSClientConfig:     cfg,
		MaxIdleConnsPerHost: 4,
		ForceAttemptHTTP2:   true,
	}
	return &http.Client{
		Transport: tr,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 5 {
				return errors.New("too many redirects")
			}
			// Downgrade https -> http would leak the credential we already set.
			if len(via) > 0 && via[0].URL.Scheme == "https" && req.URL.Scheme == "http" {
				return errors.New("refusing to follow a redirect from https to http")
			}
			return nil
		},
	}, nil
}

// Verified reports whether TLS verification was in effect, for the report.
func Verified(addr string, s TLSSettings) *bool {
	u, err := normalizeAddress(addr, "https")
	if err != nil || u.Scheme != "https" {
		return nil
	}
	v := !s.Insecure || len(s.PinSHA256) > 0
	return &v
}
