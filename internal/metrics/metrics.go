// Package metrics holds the Prometheus instrumentation. Labels are bounded by
// configuration and the database: user names, key labels, upstream and tool
// names, and fixed outcome words. Arguments, results, codes and tokens never
// become a label.
package metrics

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
	"github.com/tamcore/mcp-auth-proxy/internal/version"
)

// Tool call outcomes.
const (
	ToolSuccess       = "success"
	ToolError         = "tool_error" // the upstream answered with an error result
	ToolUpstreamError = "upstream_error"
	ToolBlocked       = "blocked"
)

// Auth tool results.
const (
	AuthGranted     = "granted"
	AuthWrongCode   = "wrong_code"
	AuthExpired     = "expired"
	AuthExhausted   = "exhausted"
	AuthNoChallenge = "no_challenge"
)

const (
	metricsNamespace = "mcp_proxy"
	labelUser        = "user"
	labelKey         = "key"
	labelUpstream    = "upstream"
	labelTool        = "tool"
	scrapeTimeout    = 5 * time.Second
)

// Who names the key behind an event: the owner's username and the key label,
// both lowercase. User is "" for a key without an owner.
type Who struct {
	User string
	Key  string
}

// WhoOf builds the labels for key; the owner's name is read from st.
func WhoOf(ctx context.Context, st *store.Store, key *store.Key) Who {
	w := Who{Key: strings.ToLower(key.Label)}
	if key.UserID != nil && st != nil {
		if u, err := st.UserByID(ctx, *key.UserID); err == nil {
			w.User = strings.ToLower(u.Username)
		}
	}
	return w
}

// KeyStates is the database view the key gauges are read from at scrape time.
type KeyStates interface {
	KeyStates(ctx context.Context, now time.Time) ([]store.KeyState, error)
}

// Metrics is the registry-bound instrumentation set.
type Metrics struct {
	registry     *prometheus.Registry
	toolCalls    *prometheus.CounterVec
	toolDuration *prometheus.HistogramVec
	auth         *prometheus.CounterVec
	challenges   *prometheus.CounterVec
}

// New registers the Go and process collectors, build_info, the event metrics,
// and, when keys is not nil, the per-key state gauges on reg (or a fresh
// registry when reg is nil).
func New(reg *prometheus.Registry, keys KeyStates, logger *slog.Logger) *Metrics {
	if reg == nil {
		reg = prometheus.NewRegistry()
	}
	m := &Metrics{
		registry: reg,
		toolCalls: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Name: "tool_calls_total",
			Help: "Proxied tool calls by user, key, upstream, tool and outcome (success, tool_error, upstream_error, blocked).",
		}, []string{labelUser, labelKey, labelUpstream, labelTool, "outcome"}),
		toolDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Namespace: metricsNamespace, Name: "tool_duration_seconds",
			Help:    "Latency of proxied tool calls that reached the upstream.",
			Buckets: []float64{0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10, 30, 60},
		}, []string{labelUpstream, labelTool}),
		auth: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Name: "auth_events_total",
			Help: "Auth tool calls by user, key and result.",
		}, []string{labelUser, labelKey, "result"}),
		challenges: prometheus.NewCounterVec(prometheus.CounterOpts{
			Namespace: metricsNamespace, Name: "challenges_total",
			Help: "One-time-code challenges created, by user and key.",
		}, []string{labelUser, labelKey}),
	}
	buildInfo := prometheus.NewGaugeVec(prometheus.GaugeOpts{
		Namespace: metricsNamespace, Name: "build_info",
		Help: "Always 1, labelled with the build identity.",
	}, []string{"version", "commit"})
	buildInfo.WithLabelValues(version.Version, version.Commit).Set(1)
	reg.MustRegister(
		collectors.NewGoCollector(),
		collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}),
		buildInfo, m.toolCalls, m.toolDuration, m.auth, m.challenges,
	)
	if keys != nil {
		reg.MustRegister(newKeyCollector(keys, logger))
	}
	return m
}

// Registry returns the underlying registry.
func (m *Metrics) Registry() *prometheus.Registry { return m.registry }

// Handler serves /metrics.
func (m *Metrics) Handler() http.Handler {
	return promhttp.HandlerFor(m.registry, promhttp.HandlerOpts{})
}

// ToolCall counts one proxied tool call; took is observed only for calls that
// reached the upstream (took > 0).
func (m *Metrics) ToolCall(w Who, upstream, tool, outcome string, took time.Duration) {
	m.toolCalls.WithLabelValues(w.User, w.Key, upstream, tool, outcome).Inc()
	if took > 0 {
		m.toolDuration.WithLabelValues(upstream, tool).Observe(took.Seconds())
	}
}

// Auth counts one auth tool call.
func (m *Metrics) Auth(w Who, result string) { m.auth.WithLabelValues(w.User, w.Key, result).Inc() }

// Challenge counts a newly created challenge.
func (m *Metrics) Challenge(w Who) { m.challenges.WithLabelValues(w.User, w.Key).Inc() }
