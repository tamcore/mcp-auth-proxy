package mcpserver

import (
	"testing"
)

// assertCount checks that one labelled counter in the proxy's registry is 1.
func assertCount(t *testing.T, p *Proxy, name string, labels map[string]string) {
	t.Helper()
	fams, err := p.metrics.Registry().Gather()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fams {
		if f.GetName() != name {
			continue
		}
		for _, m := range f.GetMetric() {
			got := map[string]string{}
			for _, lp := range m.GetLabel() {
				got[lp.GetName()] = lp.GetValue()
			}
			match := len(got) == len(labels)
			for k, v := range labels {
				match = match && got[k] == v
			}
			if match {
				if m.GetCounter().GetValue() != 1 {
					t.Fatalf("%s%v = %v, want 1", name, labels, m.GetCounter().GetValue())
				}
				return
			}
		}
	}
	t.Fatalf("%s%v is missing", name, labels)
}

// assertGateFlowMetrics checks what TestProxyGateFlow records: one blocked and
// one successful echo call, one wrong code and one grant, all under the key.
func assertGateFlowMetrics(t *testing.T, p *Proxy, keyLabel string) {
	t.Helper()
	call := func(outcome string) map[string]string {
		return map[string]string{"user": "", "key": keyLabel, "upstream": echoToolName, "tool": echoToolName,
			"outcome": outcome}
	}
	assertCount(t, p, "mcp_proxy_tool_calls_total", call("blocked"))
	assertCount(t, p, "mcp_proxy_tool_calls_total", call("success"))
	auth := func(result string) map[string]string {
		return map[string]string{"user": "", "key": keyLabel, "result": result}
	}
	assertCount(t, p, "mcp_proxy_auth_events_total", auth("wrong_code"))
	assertCount(t, p, "mcp_proxy_auth_events_total", auth("granted"))
}
