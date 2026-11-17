package webui

import (
	"sync"
	"time"
)

const (
	maxFailedLogins = 5
	loginLockout    = time.Minute
	// maxTrackedLogins bounds the limiter: every attempted name gets an entry,
	// known or not, so the response does not reveal which names exist.
	maxTrackedLogins = 10000
)

// loginLimiter locks a username for a minute after maxFailedLogins failures in
// a row; every further failure locks it again.
// ponytail: a full map evicts the oldest entry, so ~10k fresh names can unlock a name early.
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

// attempt reserves one try for username and counts it as a failure until
// reset; false means the name is locked. Check and reservation share one
// lock, so concurrent tries cannot overrun the limit.
func (l *loginLimiter) attempt(username string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	f, tracked := l.failed[username]
	if f.count >= maxFailedLogins && now.Sub(f.last) < loginLockout {
		return false
	}
	if !tracked && len(l.failed) >= maxTrackedLogins {
		l.evict(now)
	}
	l.failed[username] = failedLogins{count: f.count + 1, last: now}
	return true
}

// evict drops expired entries, or the oldest one if none expired.
func (l *loginLimiter) evict(now time.Time) {
	oldest, first := "", true
	for name, f := range l.failed {
		if now.Sub(f.last) >= loginLockout {
			delete(l.failed, name)
			continue
		}
		if first || f.last.Before(l.failed[oldest].last) {
			oldest, first = name, false
		}
	}
	if len(l.failed) >= maxTrackedLogins {
		delete(l.failed, oldest)
	}
}

func (l *loginLimiter) reset(username string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.failed, username)
}
