package web

import (
	"log/slog"
	"net/http"
	"time"
)

// withAccessLog logs one entry per request after the handler
// returns. Handler-specific logs (inbox.accepted, who.exchange,
// etc.) are emitted by the domain services on top of this baseline.
func withAccessLog(log *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		sw := &statusWriter{ResponseWriter: w, status: http.StatusOK}
		next.ServeHTTP(sw, r)
		log.Info("http_request",
			"method", r.Method,
			"path", r.URL.Path,
			"host", r.Host,
			"remote", r.RemoteAddr,
			"status", sw.status,
			"duration_ms", time.Since(start).Milliseconds(),
		)
	})
}

// statusWriter records the status code so the access logger can
// emit it alongside the request line.
type statusWriter struct {
	http.ResponseWriter
	status      int
	wroteHeader bool
}

// Unwrap exposes the wrapped ResponseWriter so http.ResponseController
// can reach optional interfaces (Flusher, Hijacker, …) it implements.
func (w *statusWriter) Unwrap() http.ResponseWriter {
	return w.ResponseWriter
}

func (w *statusWriter) WriteHeader(status int) {
	if w.wroteHeader {
		return
	}
	w.status = status
	w.wroteHeader = true
	w.ResponseWriter.WriteHeader(status)
}

func (w *statusWriter) Write(b []byte) (int, error) {
	if !w.wroteHeader {
		w.WriteHeader(http.StatusOK)
	}
	return w.ResponseWriter.Write(b)
}
