// SPDX-License-Identifier: AGPL-3.0-or-later

package inventory

import (
	"bytes"
	"strings"
	"testing"
	"time"

	"github.com/EpicMorg/enodia/internal/probe"
)

func TestRoundTrip(t *testing.T) {
	var buf bytes.Buffer
	w, err := NewWriter(&buf, "enodia/test", false)
	if err != nil {
		t.Fatal(err)
	}
	in := []probe.Observation{
		{ID: "jira", Name: "Jira Main", Product: "jira", Version: "10.3.2", CollectedAt: time.Now().UTC()},
		{ID: "tc", Name: "TeamCity", Product: "teamcity", Error: "timeout", ErrorKind: "unreachable"},
	}
	for _, o := range in {
		if err := w.Write(o); err != nil {
			t.Fatal(err)
		}
	}

	f, err := Read(bytes.NewReader(buf.Bytes()))
	if err != nil {
		t.Fatal(err)
	}
	if f.Header.SchemaVersion != SchemaVersion {
		t.Errorf("schemaVersion = %d", f.Header.SchemaVersion)
	}
	if len(f.Observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(f.Observations))
	}
	if f.Observations[0].Version != "10.3.2" {
		t.Errorf("version = %q", f.Observations[0].Version)
	}
}

// cat a.jsonl b.jsonl must produce a valid third file — the isolated-network case.
func TestConcatenatedInventories(t *testing.T) {
	mk := func(id string, at time.Time) []byte {
		var b bytes.Buffer
		w, _ := NewWriter(&b, "enodia/test", false)
		_ = w.Write(probe.Observation{ID: id, Product: "jira", Version: "10.3.2"})
		// Rewrite the header timestamp deterministically.
		out := strings.SplitN(b.String(), "\n", 2)
		hdr := strings.Replace(out[0], time.Now().UTC().Format("2006"), at.Format("2006"), 1)
		return []byte(hdr + "\n" + out[1])
	}
	older := time.Now().UTC().Add(-72 * time.Hour)
	joined := append(mk("a", older), mk("b", time.Now().UTC())...)

	f, err := Read(bytes.NewReader(joined))
	if err != nil {
		t.Fatalf("concatenated inventories must parse: %v", err)
	}
	if len(f.Observations) != 2 {
		t.Fatalf("got %d observations, want 2", len(f.Observations))
	}
}

func TestRejectsNewerSchema(t *testing.T) {
	line := `{"kind":"inventory","schemaVersion":99,"collectedAt":"2026-01-01T00:00:00Z","tool":"x"}`
	_, err := Read(strings.NewReader(line))
	if err == nil || !strings.Contains(err.Error(), "upgrade enodia") {
		t.Fatalf("a future schema must be refused with advice, got %v", err)
	}
}

func TestRejectsHeaderlessFile(t *testing.T) {
	line := `{"kind":"observation","id":"x","version":"1.0"}`
	if _, err := Read(strings.NewReader(line)); err == nil {
		t.Fatal("a file without a header must be rejected")
	}
}

// The inventory leaves the network it was collected on. Nothing secret may ride along.
func TestObservationCarriesNoCredentials(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewWriter(&buf, "enodia/test", false)
	_ = w.Write(probe.Observation{
		ID: "x", Product: "jira", Version: "10.3.2",
		Extra: map[string]string{"buildNumber": "1003002"},
	})
	for _, bad := range []string{"token", "password", "secret", "authorization", "bearer"} {
		if strings.Contains(strings.ToLower(buf.String()), bad) {
			t.Errorf("inventory contains %q", bad)
		}
	}
}
