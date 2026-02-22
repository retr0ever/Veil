package ratelimit

import (
	"net/http"
	"sync"
	"time"
)

// Bucket defines rate limit parameters.
type Bucket struct {
	MaxRequests int
	Window      time.Duration
}

// DefaultBuckets are the rate limits matching the Python backend.
var DefaultBuckets = map[string]Bucket{
	"classify": {MaxRequests: 30, Window: time.Minute},
	"proxy":    {MaxRequests: 60, Window: time.Minute},
	"auth":     {MaxRequests: 10, Window: time.Minute},
	"api":      {MaxRequests: 60, Window: time.Minute},
	"agents":   {MaxRequests: 3, Window: 5 * time.Minute},
}

// Limiter is an in-memory sliding-window rate limiter per key.
type Limiter struct {
	mu   sync.Mutex
	hits map[string][]time.Time
}

// New creates a new rate limiter.
func New() *Limiter {
	return &Limiter{hits: make(map[string][]time.Time)}
}

// Allow checks if a request identified by key is within the rate limit for the
// given bucket. Returns true if allowed.
func (l *Limiter) Allow(key string, bucket Bucket) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-bucket.Window)

	// Prune old entries
	times := l.hits[key]
	pruned := times[:0]
	for _, t := range times {
		if t.After(cutoff) {
			pruned = append(pruned, t)
		}
	}

	if len(pruned) >= bucket.MaxRequests {
		l.hits[key] = pruned
		return false
	}

	l.hits[key] = append(pruned, now)
	return true
}

// Check returns an http.StatusTooManyRequests error response if the IP is rate
// limited for the given bucket name. Returns true if the request was rejected.
func (l *Limiter) Check(w http.ResponseWriter, r *http.Request, bucketName string) bool {
	bucket, ok := DefaultBuckets[bucketName]
	if !ok {
		bucket = Bucket{MaxRequests: 60, Window: time.Minute}
	}

	ip := r.RemoteAddr
	if fwd := r.Header.Get("X-Real-IP"); fwd != "" {
		ip = fwd
	}
	key := bucketName + ":" + ip

	if l.Allow(key, bucket) {
		return false
	}

	w.Header().Set("Retry-After", itoa(int(bucket.Window.Seconds())))
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusTooManyRequests)
	w.Write([]byte(`{"error":"Rate limited","retry_after_seconds":` + itoa(int(bucket.Window.Seconds())) + `}`))
	return true
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	buf := make([]byte, 0, 10)
	for n > 0 {
		buf = append(buf, byte('0'+n%10))
		n /= 10
	}
	// reverse
	for i, j := 0, len(buf)-1; i < j; i, j = i+1, j-1 {
		buf[i], buf[j] = buf[j], buf[i]
	}
	return string(buf)
}
