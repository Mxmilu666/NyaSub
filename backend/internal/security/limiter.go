package security

import (
	"sync"
	"time"
)

// Limiter is a small in-memory failed-attempt limiter. It intentionally limits
// failures (not successful requests) and is safe for concurrent use.
type Limiter struct {
	mu       sync.Mutex
	attempts map[string]*attempt
	limit    int
	window   time.Duration
	now      func() time.Time
}

type attempt struct {
	count int
	first time.Time
}

func NewLimiter(limit int, window time.Duration) *Limiter {
	return &Limiter{attempts: make(map[string]*attempt), limit: limit, window: window, now: time.Now}
}

// Blocked reports whether key has exhausted its failure budget.
func (l *Limiter) Blocked(key string) (time.Duration, bool) {
	l.mu.Lock()
	defer l.mu.Unlock()
	a, ok := l.attempts[key]
	if !ok {
		return 0, false
	}
	elapsed := l.now().Sub(a.first)
	if elapsed >= l.window {
		delete(l.attempts, key)
		return 0, false
	}
	if a.count >= l.limit {
		return l.window - elapsed, true
	}
	return 0, false
}

// Failure records a failed attempt for key, starting a fresh window when the
// previous one expired.
func (l *Limiter) Failure(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	a, ok := l.attempts[key]
	if !ok || now.Sub(a.first) >= l.window {
		l.attempts[key] = &attempt{count: 1, first: now}
		return
	}
	a.count++
	if len(l.attempts) > 10000 {
		for k, v := range l.attempts {
			if now.Sub(v.first) >= l.window {
				delete(l.attempts, k)
			}
		}
	}
}

func (l *Limiter) Reset(key string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.attempts, key)
}
