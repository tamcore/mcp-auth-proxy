package webui

import (
	"context"
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

func TestPasswordChecksWaitForAFreeSlot(t *testing.T) {
	ui := &WebUI{passwordChecks: make(chan struct{}, maxPasswordChecks)}
	for range maxPasswordChecks {
		ui.passwordChecks <- struct{}{}
	}
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	if _, checked := ui.checkPassword(ctx, "", "pw"); checked {
		t.Fatal("a password was checked although every slot was busy")
	}
}
