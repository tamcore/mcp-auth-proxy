package webui

import (
	"strings"
	"testing"
	"time"
)

func FuzzSafeNext(f *testing.F) {
	for _, s := range []string{"/", "/portal", "//evil", "/\\evil", "https://evil", "", "javascript:x"} {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, next string) {
		got := safeNext(next)
		if !strings.HasPrefix(got, "/") || strings.HasPrefix(got, "//") || strings.HasPrefix(got, "/\\") {
			t.Fatalf("safeNext(%q) = %q leaves the site", next, got)
		}
	})
}

func FuzzSessionVerify(f *testing.F) {
	s := NewSessions([]byte("0123456789abcdef0123456789abcdef"), func() time.Time { return time.Unix(1_800_000_000, 0) })
	f.Add(s.Issue("alice"))
	f.Add("YWxpY2U.1800086400.00")
	f.Add("..")
	f.Fuzz(func(t *testing.T, cookie string) {
		name, ok := s.Verify(cookie)
		if ok && s.Issue(name) != cookie {
			t.Fatalf("accepted a cookie the signer never issued: %q", cookie)
		}
	})
}
