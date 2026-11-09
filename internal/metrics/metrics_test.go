package metrics

import (
	"testing"

	"github.com/prometheus/client_golang/prometheus"
	testutil "github.com/prometheus/client_golang/prometheus/testutil"
)

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

	if got := testutil.ToFloat64(m.tool.WithLabelValues(ToolBlocked)); got != 2 {
		t.Fatalf("blocked = %v", got)
	}
	if got := testutil.ToFloat64(m.tool.WithLabelValues(ToolAllowed)); got != 1 {
		t.Fatalf("allowed = %v", got)
	}
	if got := testutil.ToFloat64(m.tool.WithLabelValues(ToolUpstreamError)); got != 1 {
		t.Fatalf("upstream_error = %v", got)
	}
	if got := testutil.ToFloat64(m.tool.WithLabelValues(ToolWrongCode)); got != 1 {
		t.Fatalf("wrong_code = %v", got)
	}
	if got := testutil.ToFloat64(m.tool.WithLabelValues(ToolGranted)); got != 1 {
		t.Fatalf("granted = %v", got)
	}
	for r, want := range map[string]float64{
		AuthGranted: 1, AuthWrongCode: 1, AuthExpired: 1, AuthExhausted: 1, AuthNoChalleng: 1,
	} {
		if got := testutil.ToFloat64(m.auth.WithLabelValues(r)); got != want {
			t.Fatalf("auth %s = %v", r, got)
		}
	}
	if got := testutil.ToFloat64(m.challeng); got != 1 {
		t.Fatalf("challenges = %v", got)
	}
	// The registry must contain exactly the three collectors.
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	if len(fams) != 3 {
		t.Fatalf("metric families = %d", len(fams))
	}
}
