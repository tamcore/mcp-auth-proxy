package webui

import (
	"sync"
	"time"
)

const (
	maxFailedLogins = 5
	loginLockout    = time.Minute
)

// loginLimiter locks a username for a minute after maxFailedLogins failures in
// a row; every further failure locks it again. Only known users are tracked,
// so the map is bounded by the user count.
// ponytail: per username only; a password spray across many users is slowed by bcrypt alone.
type loginLimiter struct {
	mu     sync.Mutex
	failed map[string]failedLogins
	now    func() time.Time
}

type failedLogins struct {
	count int
	last  time.Time
}

func newLoginLimiter(now func() time.Time) *loginLimiter {
	if now == nil {
		now = time.Now
	}
	return &loginLimiter{failed: map[string]failedLogins{}, now: now}
}

func (l *loginLimiter) allowed(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.failed[username]
	return f.count < maxFailedLogins || l.now().Sub(f.last) >= loginLockout
}

func (l *loginLimiter) fail(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	f := l.failed[username]
	l.failed[username] = failedLogins{count: f.count + 1, last: l.now()}
}

func (l *loginLimiter) reset(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failed, username)
}
