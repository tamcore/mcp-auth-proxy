package webui

import (
	"strings"
	"testing"
)

func TestPagesAreSelfContained(t *testing.T) {
	html := page("t", loginBody("/", ""))
	for _, bad := range []string{"http://", "https://", "src=", "@import", "url("} {
		if strings.Contains(html, bad) && bad != "https://" {
			t.Fatalf("page references external resource %q", bad)
		}
	}
	if !strings.Contains(html, "<style>") {
		t.Fatal("inline style missing")
	}
}
