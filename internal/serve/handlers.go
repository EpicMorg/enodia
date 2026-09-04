// SPDX-License-Identifier: AGPL-3.0-or-later

package serve

import (
	"net/http"

	"github.com/EpicMorg/enodia/internal/render"
)

// newMux wires the fixed set of endpoints: no versioned API prefix, no
// content negotiation — a small, predictable surface matching what a
// monitoring tool sitting behind a reverse proxy actually needs.
func newMux(st *store) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", handleHealthz)
	mux.HandleFunc("/metrics", st.handleMetrics)
	mux.HandleFunc("/report.json", st.handleJSON)
	mux.HandleFunc("/", st.handleIndex)
	return mux
}

// handleHealthz never touches the snapshot: it answers as long as the
// process is up, for a reverse proxy's or orchestrator's liveness check.
func handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write([]byte("ok\n"))
}

func (s *store) handleIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	report, ok := s.snapshot(w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	if err := render.HTML(w, report, render.HTMLOptions{}); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *store) handleJSON(w http.ResponseWriter, _ *http.Request) {
	report, ok := s.snapshot(w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "application/json")
	if err := render.JSON(w, report); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func (s *store) handleMetrics(w http.ResponseWriter, _ *http.Request) {
	report, ok := s.snapshot(w)
	if !ok {
		return
	}
	w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
	if err := render.Prometheus(w, report); err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

// snapshot loads the current report, writing a 503 itself (and returning
// ok=false) if Run hasn't stored one yet — in practice this never happens
// once Run is serving, since it collects synchronously before starting the
// listener, but a handler must not assume that about every possible caller.
func (s *store) snapshot(w http.ResponseWriter) (render.Report, bool) {
	r := s.Load()
	if r == nil {
		http.Error(w, "no snapshot yet", http.StatusServiceUnavailable)
		return render.Report{}, false
	}
	return *r, true
}
