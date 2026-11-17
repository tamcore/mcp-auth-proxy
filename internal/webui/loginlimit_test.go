package webui

import (
	"fmt"
	"testing"
	"time"
)

func TestLoginLimiterStaysBounded(t *testing.T) {
	now := time.Unix(0, 0)
	l := newLoginLimiter(func() time.Time { return now })
	for i := range maxTrackedLogins + 100 {
		now = now.Add(time.Millisecond)
		if !l.attempt(fmt.Sprintf("name%d", i)) {
			t.Fatalf("first attempt of a new name refused")
		}
	}
	if len(l.failed) > maxTrackedLogins {
		t.Fatalf("limiter tracks %d names, cap is %d", len(l.failed), maxTrackedLogins)
	}
	if _, ok := l.failed["name0"]; ok {
		t.Fatal("the oldest entry must be evicted first")
	}
}
