// Package metrics holds the Prometheus instrumentation with a closed label
// vocabulary. Every counter is pre-registered with its fixed label values, so
// cardinality cannot grow at runtime.
package metrics

import (
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// Tool event results (closed vocabulary).
const (
	ToolBlocked       = "blocked"
	ToolAllowed       = "allowed"
	ToolUpstreamError = "upstream_error"
	ToolWrongCode     = "wrong_code"
	ToolGranted       = "granted"
)

// Auth event results (closed vocabulary).
const (
	AuthGranted    = "granted"
	AuthWrongCode  = "wrong_code"
	AuthExpired    = "expired"
	AuthExhausted  = "exhausted"
	AuthNoChalleng = "no_challenge"
)

// metricsNamespace is the Prometheus namespace for all collectors.
const metricsNamespace = "mcp_proxy"

// Metrics is the registry-bound instrumentation set.
type Metrics struct {
	registry *prometheus.Registry
	tool     *prometheus.CounterVec
	auth     *prometheus.CounterVec
	challeng prometheus.Counter
}

// New registers all collectors on reg (or a fresh registry when reg is nil) and
// pre-creates every label combination.
func New(reg *prometheus.Registry) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		registry: reg,
		tool: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "tool_events_total",
			Help:      "Tool call outcomes: blocked, allowed, upstream_error, wrong_code, granted.",
		}, []string{"result"}),
		auth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "auth_events_total",
			Help:      "Auth tool outcomes.",
		}, []string{"result"}),
		challeng: prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: metricsNamespace,
			Name:      "challenges_total",
			Help:      "One-time-code challenges created.",
		}),
	}
	for _, r := range []string{ToolBlocked, ToolAllowed, ToolUpstreamError, ToolWrongCode, ToolGranted} {
		m.tool.WithLabelValues(r)
	}
	for _, r := range []string{AuthGranted, AuthWrongCode, AuthExpired, AuthExhausted, AuthNoChalleng} {
		m.auth.WithLabelValues(r)
	}
	reg.MustRegister(m.tool, m.auth, m.challeng)
	return m
}

// Registry returns the underlying registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// ToolBlocked counts a blocked tool call.
func (m *Metrics) ToolBlocked() { m.tool.WithLabelValues(ToolBlocked).Inc() }

// ToolAllowed counts a proxied call that ran.
func (m *Metrics) ToolAllowed() { m.tool.WithLabelValues(ToolAllowed).Inc() }

// ToolUpstreamError counts a failed upstream call.
func (m *Metrics) ToolUpstreamError() { m.tool.WithLabelValues(ToolUpstreamError).Inc() }

// ToolWrongCode counts an auth tool call with a wrong code.
func (m *Metrics) ToolWrongCode() { m.tool.WithLabelValues(ToolWrongCode).Inc() }

// ToolGranted counts an auth tool call that granted a session.
func (m *Metrics) ToolGranted() { m.tool.WithLabelValues(ToolGranted).Inc() }

// AuthGranted counts a granted session.
func (m *Metrics) AuthGranted() { m.auth.WithLabelValues(AuthGranted).Inc() }

// AuthWrongCode counts a wrong code attempt.
func (m *Metrics) AuthWrongCode() { m.auth.WithLabelValues(AuthWrongCode).Inc() }

// AuthExpired counts an expired challenge.
func (m *Metrics) AuthExpired() { m.auth.WithLabelValues(AuthExpired).Inc() }

// AuthExhausted counts a challenge that ran out of attempts.
func (m *Metrics) AuthExhausted() { m.auth.WithLabelValues(AuthExhausted).Inc() }

// AuthNoChallenge counts a verify with no pending challenge.
func (m *Metrics) AuthNoChallenge() { m.auth.WithLabelValues(AuthNoChalleng).Inc() }

// Challenge counts a newly created challenge. Wired to Gate.OnChallenge.
func (m *Metrics) Challenge() { m.challeng.Inc() }
