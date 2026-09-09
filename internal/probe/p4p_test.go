// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"testing"
)

// p4p_2024.2.txt is a real `p4 -Ztag -p ... info` capture against a live
// production Perforce Proxy, hostnames/addresses scrubbed.
func TestP4pProbeParsesRealFixture(t *testing.T) {
	fixture := loadP4Fixture(t, "p4p_2024.2.txt")
	bin := fakeP4Binary(t, "cat <<'EOF'\n"+fixture+"EOF\n")

	p := p4pProbe{}
	obs, err := p.Probe(context.Background(), p4TestTarget(bin))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2024.2" {
		t.Fatalf("got version %q, want 2024.2", obs.Version)
	}
	if obs.Extra["backendServerVersion"] != "P4D/LINUX26X86_64/2024.2/2726408 (2025/02/27)" {
		t.Fatalf("got Extra %+v", obs.Extra)
	}
	if obs.Extra["backendServerID"] != "p4-example-commit" {
		t.Fatalf("got Extra %+v", obs.Extra)
	}
}

// A direct p4d server's reply carries no proxyVersion field at all —
// p4pProbe must reject this rather than report nothing meaningful (D9).
func TestP4pProbeRejectsDirectServer(t *testing.T) {
	fixture := loadP4Fixture(t, "p4d_2024.2.txt")
	bin := fakeP4Binary(t, "cat <<'EOF'\n"+fixture+"EOF\n")

	p := p4pProbe{}
	_, err := p.Probe(context.Background(), p4TestTarget(bin))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestP4pProbeMeta(t *testing.T) {
	m := p4pProbe{}.Meta()
	if m.Product != "p4p" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("p4 info needs no credentials")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (Perforce is proprietary, no public lifecycle calendar)", m.DefaultResolver)
	}
}
