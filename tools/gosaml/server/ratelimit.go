package server

import (
	"math"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"sync"
	"time"
)

// Rate limiting: each client gets a token bucket of RateBurst tokens that
// refills at RateLimit tokens a second, and a request takes one token. A
// client is an IPv4 address or an IPv6 /64, since one host is usually
// given a whole /64.

// maxBuckets bounds the limiter's memory. Past it, idle buckets are swept
// at once, and if that is not enough, new clients share one bucket.
const maxBuckets = 100_000

type bucket struct {
	tokens float64
	last   time.Time
}

type rateLimiter struct {
	rate  float64 // tokens a second
	burst float64

	mu        sync.Mutex
	buckets   map[netip.Prefix]*bucket
	overflow  bucket
	lastSweep time.Time
	now       func() time.Time
}

func newRateLimiter(rate float64, burst int) *rateLimiter {
	if burst < 1 {
		burst = 1
	}
	return &rateLimiter{
		rate:    rate,
		burst:   float64(burst),
		buckets: map[netip.Prefix]*bucket{},
		now:     time.Now,
	}
}

// allow takes a token from the client's bucket. When the bucket is empty
// it returns false and how long until it holds a token again.
func (l *rateLimiter) allow(client netip.Prefix) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	l.maybeSweep(now)

	b := l.buckets[client]
	if b == nil {
		if len(l.buckets) >= maxBuckets {
			b = &l.overflow
		} else {
			b = &bucket{tokens: l.burst, last: now}
			l.buckets[client] = b
		}
	}
	if b.last.IsZero() {
		b.tokens, b.last = l.burst, now
	}
	b.tokens = min(l.burst, b.tokens+now.Sub(b.last).Seconds()*l.rate)
	b.last = now
	if b.tokens >= 1 {
		b.tokens--
		return true, 0
	}
	wait := time.Duration((1 - b.tokens) / l.rate * float64(time.Second))
	return false, wait
}

// maybeSweep forgets the buckets that have refilled: they are the same as
// a new one. It runs once a minute, or at once when there are too many.
func (l *rateLimiter) maybeSweep(now time.Time) {
	if now.Sub(l.lastSweep) < time.Minute && len(l.buckets) < maxBuckets {
		return
	}
	l.lastSweep = now
	full := time.Duration(l.burst / l.rate * float64(time.Second))
	for k, b := range l.buckets {
		if now.Sub(b.last) >= full {
			delete(l.buckets, k)
		}
	}
}

// clientIP is the address of the client that sent r: the value of the
// configured header when the server is behind a proxy that sets it (on
// Fly.io, Fly-Client-IP), or else the connection's remote address.
func (s *Server) clientIP(r *http.Request) netip.Addr {
	if s.ClientIPHeader != "" {
		if a, err := netip.ParseAddr(r.Header.Get(s.ClientIPHeader)); err == nil {
			return a.Unmap()
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	a, _ := netip.ParseAddr(host)
	return a.Unmap()
}

// clientKey is the rate limiter's key for a client address.
func clientKey(a netip.Addr) netip.Prefix {
	bits := 32
	if a.Is6() {
		bits = 64
	}
	p, err := a.Prefix(bits)
	if err != nil {
		return netip.Prefix{} // an unparsable address: all share one bucket
	}
	return p
}

// rateLimited answers r with 429 Too Many Requests if its client has used
// up its bucket, and reports whether it did.
func (s *Server) rateLimited(w http.ResponseWriter, r *http.Request, ip netip.Addr) bool {
	if s.limiter == nil || r.URL.Path == "/healthz" {
		return false
	}
	ok, wait := s.limiter.allow(clientKey(ip))
	if ok {
		return false
	}
	secs := max(1, int(math.Ceil(wait.Seconds())))
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "Too many requests. Try again in "+strconv.Itoa(secs)+"s.", http.StatusTooManyRequests)
	return true
}
