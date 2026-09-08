// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// genericProbe is the escape hatch for in-house systems that will never have a
// dedicated probe. Its vocabulary is frozen at json/xml/header/plaintext/regex.
//
// It is deliberately not extended. The moment a target needs a conditional or
// a second request, it needs Go code, not more YAML. That line is what keeps
// this from turning into a badly implemented programming language.
type genericProbe struct{}

func (genericProbe) Meta() Meta {
	return Meta{
		Product:       "generic",
		Summary:       "Hand-written parser for systems Enodia does not know",
		DefaultScheme: "https",
		Auth: AuthSpec{Required: false, Kinds: []AuthKind{
			AuthNone, AuthBearer, AuthTokenHeader, AuthBasic,
		}},
	}
}

func (g genericProbe) Probe(ctx context.Context, t Target) (Observation, error) {
	start := time.Now()
	obs := Observation{
		Kind: "observation", ID: t.ID, Name: t.Name, Product: t.Product,
		CollectedAt: start.UTC(), TLSVerified: Verified(t.Address, t.TLS),
	}
	if t.Parser == nil {
		return obs, fmt.Errorf("%w: product 'generic' requires a parser block", ErrNotSupported)
	}
	ps := *t.Parser

	accept := "*/*"
	switch ps.Type {
	case "json":
		accept = "application/json"
	case "xml":
		accept = "application/xml, text/xml"
	}

	method := ""
	if ps.Type == "header" {
		method = "HEAD"
	}

	resp, err := FetchHTTP(ctx, t, Request{
		Method: method, Accept: accept,
		// Header parsers are the classic "version leaks on 403" case.
		OKStatuses: okForHeader(ps.Type),
	})
	if err != nil {
		return obs, err
	}
	defer resp.Body.Close()
	obs.Endpoint = resp.Request.URL.Path
	obs.DurationMS = time.Since(start).Milliseconds()

	var raw string
	if ps.Type == "header" {
		v := resp.Header.Get(ps.Key)
		if i := strings.LastIndexByte(v, '/'); i >= 0 {
			v = v[i+1:]
		}
		raw = v
	} else {
		body, err := ReadBody(resp)
		if err != nil {
			return obs, err
		}
		raw, err = parseBody(body, ps)
		if err != nil {
			return obs, err
		}
	}

	raw = strings.TrimSpace(raw)
	if ps.CleanRegex != "" {
		re, err := regexp.Compile(ps.CleanRegex)
		if err != nil {
			return obs, fmt.Errorf("%w: bad cleanRegex: %w", ErrUnparseable, err)
		}
		if m := re.FindStringSubmatch(raw); m != nil {
			if len(m) > 1 {
				raw = m[1]
			} else {
				raw = m[0]
			}
		}
	}
	if raw == "" {
		return obs, fmt.Errorf("%w: parser %s/%s produced nothing", ErrUnparseable, ps.Type, ps.Key)
	}
	obs.Version = raw
	return obs, nil
}

func okForHeader(t string) []int {
	if t == "header" {
		return []int{401, 403}
	}
	return nil
}

func parseBody(body []byte, ps ParserSpec) (string, error) {
	switch ps.Type {
	case "json":
		var v any
		if err := json.Unmarshal(body, &v); err != nil {
			// Services that promise JSON and return bare text are common enough
			// to be worth a fallback rather than a failure.
			line := firstLine(body)
			if line != "" {
				return line, nil
			}
			return "", fmt.Errorf("%w: not JSON: %w", ErrUnparseable, err)
		}
		got, ok := jsonPath(v, ps.Key)
		if !ok {
			return "", fmt.Errorf("%w: no value at json path %q", ErrUnparseable, ps.Key)
		}
		return scalarString(got), nil

	case "xml":
		v, ok := xmlFind(body, ps.Key)
		if !ok {
			return "", fmt.Errorf("%w: no element or attribute %q in XML", ErrUnparseable, ps.Key)
		}
		return v, nil

	case "plaintext":
		lines := strings.Split(strings.TrimSpace(string(body)), "\n")
		if ps.Line >= len(lines) {
			return "", fmt.Errorf("%w: response has %d lines, wanted line %d", ErrUnparseable, len(lines), ps.Line)
		}
		return strings.TrimSpace(lines[ps.Line]), nil

	case "regex":
		re, err := regexp.Compile(ps.Regex)
		if err != nil {
			return "", fmt.Errorf("%w: bad regex: %w", ErrUnparseable, err)
		}
		m := re.FindSubmatch(body)
		if m == nil {
			return "", fmt.Errorf("%w: regex did not match", ErrUnparseable)
		}
		if len(m) > 1 {
			return string(m[1]), nil
		}
		return string(m[0]), nil
	}
	return "", fmt.Errorf("%w: unknown parser type %q", ErrUnparseable, ps.Type)
}

func firstLine(b []byte) string {
	s := strings.TrimSpace(string(b))
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

func scalarString(v any) string {
	switch x := v.(type) {
	case string:
		return x
	case float64:
		return strconv.FormatFloat(x, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(x)
	case nil:
		return ""
	default:
		b, _ := json.Marshal(x)
		return string(b)
	}
}

// jsonPath walks a dotted path: "server.version", "items.0.version".
func jsonPath(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	cur := v
	for _, tok := range strings.Split(path, ".") {
		switch c := cur.(type) {
		case map[string]any:
			next, ok := c[tok]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(tok)
			if err != nil || i < 0 || i >= len(c) {
				return nil, false
			}
			cur = c[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// xmlFind locates "@attr" on the root, or the first element whose local name
// matches the last path segment. Matching on local name sidesteps default
// namespaces, which otherwise make a plain tag lookup silently return nothing.
func xmlFind(body []byte, key string) (string, bool) {
	if strings.HasPrefix(key, "@") {
		dec := xml.NewDecoder(strings.NewReader(string(body)))
		for {
			tok, err := dec.Token()
			if err != nil {
				return "", false
			}
			if se, ok := tok.(xml.StartElement); ok {
				for _, a := range se.Attr {
					if a.Name.Local == key[1:] {
						return a.Value, true
					}
				}
				return "", false // attributes are read from the root only
			}
		}
	}

	want := key
	for _, sep := range []string{"/", "."} {
		if i := strings.LastIndex(want, sep); i >= 0 {
			want = want[i+1:]
		}
	}
	dec := xml.NewDecoder(strings.NewReader(string(body)))
	for {
		tok, err := dec.Token()
		if err != nil {
			return "", false
		}
		se, ok := tok.(xml.StartElement)
		if !ok || se.Name.Local != want {
			continue
		}
		var sb strings.Builder
		for {
			t2, err := dec.Token()
			if err != nil {
				return "", false
			}
			switch v := t2.(type) {
			case xml.CharData:
				sb.Write(v)
			case xml.EndElement:
				if v.Name.Local == want {
					s := strings.TrimSpace(sb.String())
					return s, s != ""
				}
			}
		}
	}
}
