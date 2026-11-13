package metrics

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

// keyCollector reads the key gauges from the database on every scrape, so they
// stay right across restarts and need no bookkeeping on the request path.
type keyCollector struct {
	keys   KeyStates
	logger *slog.Logger
	now    func() time.Time

	lastSeen, lastSuccess, lastAuthorized, authorizedUntil, authorized, pending *prometheus.Desc
}

func newKeyCollector(keys KeyStates, logger *slog.Logger) *keyCollector {
	if logger == nil {
		logger = slog.Default()
	}
	desc := func(name, help string) *prometheus.Desc {
		return prometheus.NewDesc(prometheus.BuildFQName(metricsNamespace, "key", name), help,
			[]string{labelUser, labelKey}, nil)
	}
	return &keyCollector{
		keys: keys, logger: logger, now: time.Now,
		lastSeen:        desc("last_seen_timestamp_seconds", "Last authenticated request with the key."),
		lastSuccess:     desc("last_success_timestamp_seconds", "Last proxied tool call with the key that succeeded."),
		lastAuthorized:  desc("last_authorized_timestamp_seconds", "Start of the key's current or last session."),
		authorizedUntil: desc("authorized_until_timestamp_seconds", "End of the key's current or last session."),
		authorized:      desc("authorized", "1 while the key has a live session."),
		pending:         desc("auth_pending", "1 while the key has an open, unexpired one-time-code challenge."),
	}
}

// Describe implements prometheus.Collector.
func (c *keyCollector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{c.lastSeen, c.lastSuccess, c.lastAuthorized, c.authorizedUntil,
		c.authorized, c.pending} {
		ch <- d
	}
}

// keyRow is one (user, key) series set; keys sharing a label are merged.
type keyRow struct {
	lastSeen, lastSuccess, lastAuthorized, authorizedUntil time.Time
	pending                                                bool
}

// Collect implements prometheus.Collector.
func (c *keyCollector) Collect(ch chan<- prometheus.Metric) {
	ctx, cancel := context.WithTimeout(context.Background(), scrapeTimeout)
	defer cancel()
	now := c.now()
	states, err := c.keys.KeyStates(ctx, now)
	if err != nil {
		c.logger.Warn("metrics: read key states", "error", err)
		ch <- prometheus.NewInvalidMetric(c.lastSeen, err)
		return
	}
	for w, r := range mergeKeys(states) {
		c.emitTime(ch, c.lastSeen, r.lastSeen, w)
		c.emitTime(ch, c.lastSuccess, r.lastSuccess, w)
		c.emitTime(ch, c.lastAuthorized, r.lastAuthorized, w)
		c.emitTime(ch, c.authorizedUntil, r.authorizedUntil, w)
		ch <- prometheus.MustNewConstMetric(c.authorized, prometheus.GaugeValue, boolValue(now.Before(r.authorizedUntil)),
			w.User, w.Key)
		ch <- prometheus.MustNewConstMetric(c.pending, prometheus.GaugeValue, boolValue(r.pending), w.User, w.Key)
	}
}

// emitTime skips a timestamp that never happened instead of reporting 1970.
func (c *keyCollector) emitTime(ch chan<- prometheus.Metric, d *prometheus.Desc, t time.Time, w Who) {
	if t.IsZero() {
		return
	}
	ch <- prometheus.MustNewConstMetric(d, prometheus.GaugeValue, float64(t.UnixNano())/1e9, w.User, w.Key)
}

// mergeKeys groups states by lowercase (user, key label): two keys of one user
// with the same label would otherwise be duplicate series and fail the scrape.
func mergeKeys(states []store.KeyState) map[Who]keyRow {
	out := map[Who]keyRow{}
	for _, s := range states {
		w := Who{User: strings.ToLower(s.Username), Key: strings.ToLower(s.Label)}
		r := out[w]
		r.lastSeen = later(r.lastSeen, s.LastUsedAt)
		r.lastSuccess = later(r.lastSuccess, s.LastSuccessAt)
		r.lastAuthorized = later(r.lastAuthorized, s.AuthorizedAt)
		r.authorizedUntil = later(r.authorizedUntil, s.AuthorizedUntil)
		r.pending = r.pending || s.AuthPending
		out[w] = r
	}
	return out
}

func later(a time.Time, b *time.Time) time.Time {
	if b != nil && b.After(a) {
		return *b
	}
	return a
}

func boolValue(b bool) float64 {
	if b {
		return 1
	}
	return 0
}
