// SPDX-License-Identifier: AGPL-3.0-or-later

// Package inventory reads and writes the JSONL inventory file.
//
// The format is one JSON object per line: a header, then one observation per
// service. Concatenating two files with cat produces a valid third file, which
// is exactly what an estate split across isolated networks needs.
package inventory

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

// SchemaVersion is bumped whenever the on-disk shape changes. An inventory
// written today may well be evaluated a year from now.
const SchemaVersion = 1

// Header is the first line of an inventory file.
type Header struct {
	Kind          string    `json:"kind"` // "inventory"
	SchemaVersion int       `json:"schemaVersion"`
	CollectedAt   time.Time `json:"collectedAt"`
	Tool          string    `json:"tool"`
	Redacted      bool      `json:"redacted,omitempty"`
}

// Writer emits an inventory as JSON Lines.
type Writer struct {
	enc *json.Encoder
}

func NewWriter(w io.Writer, tool string, redacted bool) (*Writer, error) {
	enc := json.NewEncoder(w)
	h := Header{
		Kind:          "inventory",
		SchemaVersion: SchemaVersion,
		CollectedAt:   time.Now().UTC(),
		Tool:          tool,
		Redacted:      redacted,
	}
	if err := enc.Encode(h); err != nil {
		return nil, fmt.Errorf("writing inventory header: %w", err)
	}
	return &Writer{enc: enc}, nil
}

func (w *Writer) Write(o probe.Observation) error {
	o.Kind = "observation"
	if err := w.enc.Encode(o); err != nil {
		return fmt.Errorf("writing observation %s: %w", o.ID, err)
	}
	return nil
}

// File is a fully parsed inventory.
type File struct {
	Header       Header
	Observations []probe.Observation
}

// Read parses an inventory. Extra headers are tolerated so that
// `cat a.jsonl b.jsonl` works; the earliest collection time wins, because a
// merged inventory is only as fresh as its oldest part.
func Read(r io.Reader) (*File, error) {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 8*1024*1024)

	out := &File{}
	seenHeader := false
	line := 0

	for sc.Scan() {
		line++
		raw := strings.TrimSpace(sc.Text())
		if raw == "" || strings.HasPrefix(raw, "#") {
			continue
		}
		var probeKind struct {
			Kind string `json:"kind"`
		}
		if err := json.Unmarshal([]byte(raw), &probeKind); err != nil {
			return nil, fmt.Errorf("line %d is not valid JSON: %w", line, err)
		}

		switch probeKind.Kind {
		case "inventory":
			var h Header
			if err := json.Unmarshal([]byte(raw), &h); err != nil {
				return nil, fmt.Errorf("line %d: bad header: %w", line, err)
			}
			if h.SchemaVersion > SchemaVersion {
				return nil, fmt.Errorf(
					"inventory uses schema version %d, this build understands up to %d — upgrade enodia",
					h.SchemaVersion, SchemaVersion)
			}
			if !seenHeader || h.CollectedAt.Before(out.Header.CollectedAt) {
				out.Header = h
			}
			seenHeader = true

		case "observation":
			var o probe.Observation
			if err := json.Unmarshal([]byte(raw), &o); err != nil {
				return nil, fmt.Errorf("line %d: bad observation: %w", line, err)
			}
			out.Observations = append(out.Observations, o)

		default:
			return nil, fmt.Errorf("line %d: unknown kind %q", line, probeKind.Kind)
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("reading inventory: %w", err)
	}
	if !seenHeader {
		return nil, fmt.Errorf("no inventory header found; is this an enodia inventory?")
	}
	return out, nil
}

// Age reports how stale the inventory is relative to now. Evaluation uses the
// collection time, not the wall clock, so a month-old file is not silently
// judged against today.
func (f *File) Age(now time.Time) time.Duration { return now.Sub(f.Header.CollectedAt) }
