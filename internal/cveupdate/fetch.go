// SPDX-License-Identifier: AGPL-3.0-or-later

package cveupdate

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// WantsFromInventory reads which OVAL releases, Alpine branches and
// PostgreSQL majors an inventory's observations need, the same way the
// package and CVE lookups key them.
func WantsFromInventory(obs []probe.Observation) Wants {
	var w Wants
	for _, o := range obs {
		major, _, _ := strings.Cut(o.Version, ".")
		switch o.Product {
		case "ubuntu", "linuxmint":
			if c := o.Extra["codename"]; c != "" {
				w.OVAL = append(w.OVAL, "ubuntu:"+c)
			}
		case "rhel", "rocky-linux", "almalinux", "oracle-linux":
			if major != "" {
				w.OVAL = append(w.OVAL, o.Product+":"+major)
			}
		case "astra-linux", "redos":
			if parts := strings.SplitN(o.Version, ".", 3); len(parts) >= 2 {
				w.OVAL = append(w.OVAL, o.Product+":"+parts[0]+"."+parts[1])
			}
		case "alpine-linux":
			if parts := strings.SplitN(o.Version, ".", 3); len(parts) >= 2 {
				w.Alpine = append(w.Alpine, "v"+parts[0]+"."+parts[1])
			}
		case "postgresql":
			if m, ok := postgresMajor(o.Version); ok {
				w.PostgreSQL = append(w.PostgreSQL, m)
			}
		}
	}
	return w
}

// TLSOptions is cve.update's TLS block.
type TLSOptions struct {
	SkipVerify bool
	CAFile     string // added to the system roots
	CADir      string // every certificate in it, added to the system roots
}

// Client downloads Items.
type Client struct {
	HTTP      *http.Client
	UserAgent string
	Attempts  int           // tries per file, on a network error, 429 or 5xx
	Backoff   time.Duration // wait before the second try, doubled after
}

// NewClient returns a Client verifying TLS as opts say.
func NewClient(opts TLSOptions, userAgent string) (*Client, error) {
	cfg := &tls.Config{MinVersion: tls.VersionTLS12}
	if opts.SkipVerify {
		cfg.InsecureSkipVerify = true // cve.update.tls_skip_verify: the operator's explicit choice
	} else if opts.CAFile != "" || opts.CADir != "" {
		pool, err := x509.SystemCertPool()
		if err != nil {
			pool = x509.NewCertPool()
		}
		var files []string
		if opts.CAFile != "" {
			files = append(files, opts.CAFile)
		}
		if opts.CADir != "" {
			entries, err := os.ReadDir(opts.CADir)
			if err != nil {
				return nil, fmt.Errorf("cve.update.ca_dir: %w", err)
			}
			for _, e := range entries {
				if !e.IsDir() {
					files = append(files, filepath.Join(opts.CADir, e.Name()))
				}
			}
		}
		added := 0
		for _, f := range files {
			n, err := addCerts(pool, f)
			if err != nil && f == opts.CAFile {
				return nil, fmt.Errorf("cve.update.ca_file: %w", err)
			}
			added += n
		}
		if added == 0 {
			return nil, errors.New("cve.update: no certificates found in ca_file/ca_dir")
		}
		cfg.RootCAs = pool
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = cfg
	tr.DialContext = (&net.Dialer{Timeout: 30 * time.Second, KeepAlive: 30 * time.Second}).DialContext
	tr.ResponseHeaderTimeout = 2 * time.Minute
	return &Client{
		HTTP:      &http.Client{Transport: tr},
		UserAgent: userAgent,
		Attempts:  3,
		Backoff:   5 * time.Second,
	}, nil
}

// addCerts adds every certificate in file — PEM, one or many, or a single
// DER — to pool.
func addCerts(pool *x509.CertPool, file string) (int, error) {
	raw, err := os.ReadFile(file)
	if err != nil {
		return 0, err
	}
	// `cat root.crt sub.crt > bundle.pem` with no newline at the end of
	// root.crt glues the two armour lines together, which pem.Decode
	// can't read past — seen with the Russian Trusted Root CA's own file.
	raw = bytes.ReplaceAll(raw, []byte("-----END CERTIFICATE----------BEGIN"), []byte("-----END CERTIFICATE-----\n-----BEGIN"))
	n := 0
	for rest := raw; ; {
		var b *pem.Block
		b, rest = pem.Decode(rest)
		if b == nil {
			break
		}
		if b.Type != "CERTIFICATE" {
			continue
		}
		if c, err := x509.ParseCertificate(b.Bytes); err == nil {
			pool.AddCert(c)
			n++
		}
	}
	if n == 0 {
		c, err := x509.ParseCertificate(raw)
		if err != nil {
			return 0, fmt.Errorf("%s: no PEM or DER certificate", file)
		}
		pool.AddCert(c)
		n = 1
	}
	return n, nil
}

// Status is what Fetch did with an Item.
type Status string

const (
	New    Status = "new"    // downloaded, checked, in place
	Same   Status = "same"   // unchanged upstream; the file on disk kept
	Failed Status = "failed" // nothing replaced; Err says why
)

// Result is one Item's outcome.
type Result struct {
	Item   Item
	Status Status
	Err    error
}

// tmpDirName is where a download waits for its check, next to its
// destination: same filesystem, so the rename is atomic, and a
// subdirectory, which the loaders reading cve.*.path directories skip.
const tmpDirName = ".enodia-update"

// Fetch downloads it. An existing file is sent as If-Modified-Since its
// modification time; a 304 keeps it. A download is written beside the
// destination, checked by the same loader the CVE lookup will use, then
// renamed over it with the server's Last-Modified as its time — so a
// failed or broken download never replaces a working file. A source with
// no Last-Modified is compared byte for byte instead.
func (c *Client) Fetch(ctx context.Context, it Item) Result {
	fail := func(err error) Result { return Result{Item: it, Status: Failed, Err: err} }

	tmpDir := filepath.Join(filepath.Dir(it.Dest), tmpDirName)
	if err := os.MkdirAll(tmpDir, 0o755); err != nil {
		return fail(err)
	}
	defer os.Remove(tmpDir) // only once empty: a parallel run's files stay
	tmp := filepath.Join(tmpDir, filepath.Base(it.Dest))
	defer os.Remove(tmp)

	var since time.Time
	if st, err := os.Stat(it.Dest); err == nil && st.Size() > 0 {
		since = st.ModTime()
	}
	modified, notModified, err := c.download(ctx, it.URL, since, tmp)
	switch {
	case err != nil:
		return fail(err)
	case notModified:
		removeAll(it.replaces)
		return Result{Item: it, Status: Same}
	}
	if it.check != nil {
		if err := it.check(tmp); err != nil {
			return fail(fmt.Errorf("downloaded file doesn't load, kept the old one: %w", err))
		}
	}
	if modified.IsZero() && sameContent(tmp, it.Dest) {
		return Result{Item: it, Status: Same}
	}
	if err := os.Rename(tmp, it.Dest); err != nil {
		return fail(err)
	}
	if !modified.IsZero() {
		_ = os.Chtimes(it.Dest, modified, modified)
	}
	removeAll(it.replaces)
	return Result{Item: it, Status: New}
}

func removeAll(paths []string) {
	for _, p := range paths {
		_ = os.Remove(p)
	}
}

// download GETs url into dest, retrying a network error, 429 or 5xx.
func (c *Client) download(ctx context.Context, url string, since time.Time, dest string) (modified time.Time, notModified bool, err error) {
	wait := c.Backoff
	for attempt := 1; ; attempt++ {
		modified, notModified, retry, err := c.try(ctx, url, since, dest)
		if err == nil || !retry || attempt >= c.Attempts {
			return modified, notModified, err
		}
		select {
		case <-ctx.Done():
			return time.Time{}, false, ctx.Err()
		case <-time.After(wait):
		}
		wait *= 2
	}
}

func (c *Client) try(ctx context.Context, url string, since time.Time, dest string) (modified time.Time, notModified, retry bool, err error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return time.Time{}, false, false, err
	}
	req.Header.Set("User-Agent", c.UserAgent)
	if !since.IsZero() {
		req.Header.Set("If-Modified-Since", since.UTC().Format(http.TimeFormat))
	}
	resp, err := c.HTTP.Do(req)
	if err != nil {
		return time.Time{}, false, true, err
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusNotModified:
		return time.Time{}, true, false, nil
	case resp.StatusCode == http.StatusTooManyRequests || resp.StatusCode >= 500:
		return time.Time{}, false, true, fmt.Errorf("%s: %s", url, resp.Status)
	case resp.StatusCode != http.StatusOK:
		return time.Time{}, false, false, fmt.Errorf("%s: %s", url, resp.Status)
	}

	f, err := os.Create(dest)
	if err != nil {
		return time.Time{}, false, false, err
	}
	n, err := io.Copy(f, resp.Body)
	if cerr := f.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return time.Time{}, false, true, fmt.Errorf("%s: %w", url, err)
	}
	if resp.ContentLength > 0 && n != resp.ContentLength {
		return time.Time{}, false, true, fmt.Errorf("%s: got %d of %d bytes", url, n, resp.ContentLength)
	}
	if lm, err := http.ParseTime(resp.Header.Get("Last-Modified")); err == nil {
		modified = lm
	}
	return modified, false, false, nil
}

func sameContent(a, b string) bool {
	x, err := os.ReadFile(a)
	if err != nil {
		return false
	}
	y, err := os.ReadFile(b)
	return err == nil && bytes.Equal(x, y)
}
