package metrics

import (
	"context"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tamcore/mcp-auth-proxy/internal/store"
)

func TestInvalidUTF8AndLongLabelsNeverBreakTheScrape(t *testing.T) {
	m := New(nil, fakeKeys{{Username: "bad\xffuser", Label: "key\xff" + strings.Repeat("x", 500)}}, nil)
	m.ToolCall(Who{User: "u", Key: "k"}, "up\xff", "tool\xff", ToolSuccess, 1)
	fams, err := m.Registry().Gather()
	if err != nil {
		t.Fatalf("a stored label with invalid UTF-8 must not fail /metrics: %v", err)
	}
	for _, f := range fams {
		for _, mt := range f.GetMetric() {
			for _, lp := range mt.GetLabel() {
				if len([]rune(lp.GetValue())) > maxLabelRunes {
					t.Fatalf("%s{%s} is %d runes long", f.GetName(), lp.GetName(), len([]rune(lp.GetValue())))
				}
			}
		}
	}
}

func TestToolNamesFromOneUpstreamAreCapped(t *testing.T) {
	m := New(nil, nil, nil)
	for i := range maxToolSeries + 50 {
		m.ToolCall(Who{User: testUser, Key: testKey}, "own", fmt.Sprintf("tool_%d", i), ToolSuccess, 1)
	}
	tools := map[string]bool{}
	for _, mt := range family(t, m, "mcp_proxy_tool_calls_total").GetMetric() {
		for _, lp := range mt.GetLabel() {
			if lp.GetName() == labelTool {
				tools[lp.GetValue()] = true
			}
		}
	}
	if len(tools) > maxToolSeries+1 || !tools[otherTool] {
		t.Fatalf("an upstream that keeps renaming tools must not grow the series without bound: %d tools", len(tools))
	}
}

func TestOwnerLookupFailureIsNotAnOwnerlessKey(t *testing.T) {
	st, err := store.Open(context.Background(), filepath.Join(t.TempDir(), "proxy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	missing := "u_missing"
	w := WhoOf(context.Background(), st, &store.Key{Label: "Mistral", UserID: &missing})
	if w.User != unknownUser || w.Key != testKey {
		t.Fatalf("who: %+v", w)
	}
}
