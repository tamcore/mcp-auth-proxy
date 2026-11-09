package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// counterValue reads the value of one counter (identified by its "result"
// label) out of the gathered registry.
func counterValue(t *testing.T, m *Metrics, family, result string) float64 {
	t.Helper()
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != family {
			continue
		}
		for _, metric := range f.GetMetric() {
			for _, lp := range metric.GetLabel() {
				if lp.GetName() == "result" && lp.GetValue() == result {
					return metric.GetCounter().GetValue()
				}
			}
		}
	}
	return 0
}

func TestClosedVocabularyCounts(t *testing.T) {
	m := New(prometheus.NewRegistry())
	m.ToolBlocked()
	m.ToolBlocked()
	m.ToolAllowed()
	m.ToolUpstreamError()
	m.ToolWrongCode()
	m.ToolGranted()
	m.AuthGranted()
	m.AuthWrongCode()
	m.AuthExpired()
	m.AuthExhausted()
	m.AuthNoChallenge()
	m.Challenge()

	tool := "mcp_proxy_tool_events_total"
	auth := "mcp_proxy_auth_events_total"
	want := map[[2]string]float64{
		{tool, ToolBlocked}: 2, {tool, ToolAllowed}: 1, {tool, ToolUpstreamError}: 1,
		{tool, ToolWrongCode}: 1, {tool, ToolGranted}: 1,
		{auth, AuthGranted}: 1, {auth, AuthWrongCode}: 1, {auth, AuthExpired}: 1,
		{auth, AuthExhausted}: 1, {auth, AuthNoChalleng}: 1,
	}
	for key, w := range want {
		if got := counterValue(t, m, key[0], key[1]); got != w {
			t.Fatalf("%s{%s} = %v, want %v", key[0], key[1], got, w)
		}
	}
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 3 {
		t.Fatalf("metric families = %d, want 3", len(fams))
	}
	var found bool
	for _, f := range fams {
		if f.GetName() == "mcp_proxy_challenges_total" {
			found = true
			if got := f.GetMetric()[0].GetCounter().GetValue(); got != 1 {
				t.Fatalf("challenges = %v", got)
			}
		}
	}
	if !found {
		t.Fatal("challenges counter missing")
	}
}
