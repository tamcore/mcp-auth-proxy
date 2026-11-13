package server

import (
	"log/slog"
	"net/http"
	"strings"
	"time"
)

// logPath returns the request path safe for logs: everything after the first
// credential marker is redacted, also when a client embeds the resource path
// in a well-known URL, and the query (signatures, OAuth codes) is dropped.
func logPath(p string) string {
	cut, marker := -1, ""
	for _, m := range []string{"/mcp/", "/invite/"} {
		if i := strings.Index(p, m); i >= 0 && len(p) > i+len(m) && (cut < 0 || i < cut) {
			cut, marker = i, m
		}
	}
	if cut < 0 {
		return p
	}
	return p[:cut] + marker + "[redacted]"
}

type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
}

func (r *statusRecorder) WriteHeader(code int) {
	r.status = code
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if r.status == 0 {
		r.status = http.StatusOK
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

// Unwrap lets http.ResponseController reach the real writer (SSE flushes).
func (r *statusRecorder) Unwrap() http.ResponseWriter { return r.ResponseWriter }

func (r *statusRecorder) Flush() {
	if f, ok := r.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// accessLog logs every request once it is served.
func accessLog(logger *slog.Logger, next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()
		rec := &statusRecorder{ResponseWriter: w}
		next.ServeHTTP(rec, r)
		logger.Info("http request",
			"method", r.Method,
			"path", logPath(r.URL.Path),
			"status", rec.status,
			"bytes", rec.bytes,
			"duration_ms", time.Since(start).Milliseconds(),
			"remote", r.RemoteAddr,
			"forwarded_for", r.Header.Get("X-Forwarded-For"),
			"user_agent", r.UserAgent(),
		)
	})
}
