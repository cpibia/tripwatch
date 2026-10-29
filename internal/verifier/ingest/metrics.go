package ingest

import (
	"net/http"
	"slices"
	"strings"
	"sync"

	"github.com/cpibia/tripwatch/internal/protocol"
)

// Count is how many requests of one kind got one answer since the verifier started.
type Count struct {
	Kind   string
	Status int
	N      uint64
}

// counters counts the requests by kind and answer. The keys are bounded: the kinds are the
// protocol's, anything else is "other", and the answers are the few this server writes.
type counters struct {
	mu sync.Mutex
	n  map[Count]uint64
}

func (c *counters) add(kind string, status int) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.n == nil {
		c.n = map[Count]uint64{}
	}
	c.n[Count{Kind: kind, Status: status}]++
}

// Counts returns the requests counted so far, in a stable order.
func (s *Server) Counts() []Count {
	s.counts.mu.Lock()
	out := make([]Count, 0, len(s.counts.n))
	for k, n := range s.counts.n {
		k.N = n
		out = append(out, k)
	}
	s.counts.mu.Unlock()
	slices.SortFunc(out, func(a, b Count) int {
		if c := strings.Compare(a.Kind, b.Kind); c != 0 {
			return c
		}
		return a.Status - b.Status
	})
	return out
}

// requestKind names a request for the counters, from its path and kind header.
func requestKind(r *http.Request) string {
	switch r.URL.Path {
	case EnrollPath:
		return "enroll"
	case RenewPath:
		return "renew"
	}
	switch k := protocol.Kind(r.Header.Get(KindHeader)); k {
	case protocol.KindSnapshot, protocol.KindHeartbeat, protocol.KindEvent:
		return string(k)
	}
	return "other"
}

// statusWriter remembers the status written, for the counters.
type statusWriter struct {
	http.ResponseWriter
	status int
}

func (w *statusWriter) WriteHeader(code int) {
	if w.status == 0 {
		w.status = code
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	return w.ResponseWriter.Write(b)
}

// Unwrap lets http.ResponseController reach the connection's deadlines.
func (w *statusWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
