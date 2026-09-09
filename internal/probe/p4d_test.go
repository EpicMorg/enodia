// SPDX-License-Identifier: AGPL-3.0-or-later

package probe

import (
	"context"
	"errors"
	"testing"
)

// p4d_2024.2.txt is a real `p4 -Ztag -p ... info` capture against a live
// production Perforce Helix Core server, hostnames/addresses scrubbed.
func TestP4dProbeParsesRealFixture(t *testing.T) {
	fixture := loadP4Fixture(t, "p4d_2024.2.txt")
	bin := fakeP4Binary(t, "cat <<'EOF'\n"+fixture+"EOF\n")

	p := p4dProbe{}
	obs, err := p.Probe(context.Background(), p4TestTarget(bin))
	if err != nil {
		t.Fatalf("Probe: %v", err)
	}
	if obs.Version != "2024.2" {
		t.Fatalf("got version %q, want 2024.2", obs.Version)
	}
	if obs.Extra["serverID"] != "p4-example-commit" {
		t.Fatalf("got Extra %+v", obs.Extra)
	}
	if obs.Extra["serverServices"] != "commit-server" {
		t.Fatalf("got Extra %+v", obs.Extra)
	}
}

// A real Perforce Proxy answers `info` with the backend's own
// serverVersion unchanged, plus its own proxyVersion — p4dProbe must
// reject this rather than silently report the backend's version as if
// this address were the server itself (D9).
func TestP4dProbeRejectsProxy(t *testing.T) {
	fixture := loadP4Fixture(t, "p4p_2024.2.txt")
	bin := fakeP4Binary(t, "cat <<'EOF'\n"+fixture+"EOF\n")

	p := p4dProbe{}
	_, err := p.Probe(context.Background(), p4TestTarget(bin))
	if !errors.Is(err, ErrNotSupported) {
		t.Fatalf("got %v, want ErrNotSupported", err)
	}
}

func TestP4dProbeMeta(t *testing.T) {
	m := p4dProbe{}.Meta()
	if m.Product != "p4d" {
		t.Fatalf("got product %q", m.Product)
	}
	if m.Auth.Required {
		t.Fatal("p4 info needs no credentials")
	}
	if m.DefaultResolver.Type != "" {
		t.Fatalf("got resolver %+v, want none (Perforce is proprietary, no public lifecycle calendar)", m.DefaultResolver)
	}
}
