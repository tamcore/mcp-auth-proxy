package webui

import (
	"sync"
	"time"
)

const (
	maxFailedLogins = 5
	loginLockout    = time.Minute
	// unknownUsersKey is the one shared entry for all unknown usernames; the
	// NUL byte keeps it apart from every real username.
	unknownUsersKey = "\x00unknown"
)

// loginLimiter locks a username for a minute after maxFailedLogins failures in
// a row; every further failure locks it again. Unknown usernames share one
// entry, so rotating names neither escapes the lock nor grows the map: it is
// bounded by the user count plus one.
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
