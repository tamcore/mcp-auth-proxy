package metrics

import (
	"context"
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

const (
	testUser = "philipp"
	testKey  = "mistral"
)

// family returns the gathered metric family name, or nil.
func family(t *testing.T, m *Metrics, name string) *dto.MetricFamily {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() == name {
			return f
		}
	}
	return nil
}

// series returns the metric in family name whose labels include want.
func series(t *testing.T, m *Metrics, name string, want map[string]string) *dto.Metric {
	t.Helper()
	f := family(t, m, name)
	if f == nil {
		return nil
	}
	for _, metric := range f.GetMetric() {
		got := map[string]string{}
		for _, lp := range metric.GetLabel() {
			got[lp.GetName()] = lp.GetValue()
		}
		match := true
		for k, v := range want {
			if got[k] != v {
				match = false
			}
		}
		if match {
			return metric
		}
	}
	return nil
}

func TestStandardCollectorsAndBuildInfo(t *testing.T) {
	m := New(nil, nil, nil)
	for _, name := range []string{"go_goroutines", "go_memstats_heap_alloc_bytes", "mcp_proxy_build_info"} {
		if family(t, m, name) == nil {
			t.Fatalf("%s is not exported", name)
		}
	}
}

func TestToolCallsAreLabelledByUserKeyToolAndOutcome(t *testing.T) {
	m := New(nil, nil, nil)
	who := Who{User: testUser, Key: testKey}
	m.ToolCall(who, "garmin", "get_activities", ToolSuccess, 2*time.Second)
	m.ToolCall(who, "garmin", "get_activities", ToolSuccess, time.Second)
	m.ToolCall(who, "garmin", "get_activities", ToolBlocked, 0)
	m.Auth(who, AuthWrongCode)
	m.Challenge(who)

	labels := map[string]string{labelUser: testUser, labelKey: testKey, labelUpstream: "garmin",
		labelTool: "get_activities", "outcome": ToolSuccess}
	if s := series(t, m, "mcp_proxy_tool_calls_total", labels); s == nil || s.GetCounter().GetValue() != 2 {
		t.Fatalf("successful calls: %v", s)
	}
	labels["outcome"] = ToolBlocked
	if s := series(t, m, "mcp_proxy_tool_calls_total", labels); s == nil || s.GetCounter().GetValue() != 1 {
		t.Fatalf("blocked calls: %v", s)
	}
	h := series(t, m, "mcp_proxy_tool_duration_seconds", map[string]string{labelTool: "get_activities"})
	if h == nil || h.GetHistogram().GetSampleCount() != 2 {
		t.Fatalf("a blocked call never reached the upstream and has no latency: %v", h)
	}
	authLabels := map[string]string{labelUser: testUser, "result": AuthWrongCode}
	if s := series(t, m, "mcp_proxy_auth_events_total", authLabels); s == nil {
		t.Fatal("auth result not labelled by user")
	}
	if s := series(t, m, "mcp_proxy_challenges_total", map[string]string{labelKey: testKey}); s == nil {
		t.Fatal("challenge not labelled by key")
	}
}

type fakeKeys []store.KeyState

func (f fakeKeys) KeyStates(context.Context, time.Time) ([]store.KeyState, error) { return f, nil }

func TestKeyGaugesFromTheDatabase(t *testing.T) {
	now := time.Now()
	seen, until, earlier := now.Add(-time.Minute), now.Add(time.Hour), now.Add(-time.Hour)
	m := New(nil, fakeKeys{
		{Username: "Philipp", Label: "Mistral", LastUsedAt: &seen, AuthorizedAt: &earlier, AuthorizedUntil: &until},
		{Username: "philipp", Label: "mistral", AuthPending: true}, // same label: merged, not a duplicate series
		{Label: "cli"},
	}, nil)
	mistral := map[string]string{labelUser: testUser, labelKey: testKey}
	gauge := func(name string, labels map[string]string) *dto.Metric {
		return series(t, m, "mcp_proxy_key_"+name, labels)
	}
	if g := gauge("last_seen_timestamp_seconds", mistral); g == nil || int64(g.GetGauge().GetValue()) != seen.Unix() {
		t.Fatalf("last seen: %v", g)
	}
	g := gauge("authorized_until_timestamp_seconds", mistral)
	if g == nil || int64(g.GetGauge().GetValue()) != until.Unix() {
		t.Fatalf("authorized until: %v", g)
	}
	if g := gauge("authorized", mistral); g == nil || g.GetGauge().GetValue() != 1 {
		t.Fatalf("authorized: %v", g)
	}
	if g := gauge("auth_pending", mistral); g == nil || g.GetGauge().GetValue() != 1 {
		t.Fatalf("auth pending: %v", g)
	}
	cli := map[string]string{labelUser: "", labelKey: "cli"}
	if g := gauge("last_seen_timestamp_seconds", cli); g != nil {
		t.Fatal("a key never seen must not report 1970")
	}
	if g := gauge("authorized", cli); g == nil || g.GetGauge().GetValue() != 0 {
		t.Fatalf("an ownerless, unauthorized key: %v", g)
	}
}
