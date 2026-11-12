package ntfy

import (
	"net/url"
	"strings"
	"testing"
)

func FuzzBaseURL(f *testing.F) {
	for _, s := range []string{"https://ntfy.sh", "http://127.0.0.1:1", "http://ntfy.example", "https://u:p@x", "ntfy.sh"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, raw string) {
		base, err := baseURL(raw)
		if err != nil {
			return
		}
		u, perr := url.Parse(base)
		if perr != nil || u.User != nil || u.RawQuery != "" {
			t.Fatalf("baseURL(%q) = %q is not a clean base URL", raw, base)
		}
		if !strings.HasPrefix(base, "https://") && !isLoopback(u.Hostname()) {
			t.Fatalf("baseURL(%q) = %q allows plain http to a non-loopback host", raw, base)
		}
	})
}
