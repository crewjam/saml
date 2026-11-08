package server

import (
	"bytes"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/tools/gosaml/store"
)

func newTestServer(t *testing.T, cfg Config) *Server {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg.BaseURL, cfg.Store, cfg.TTL, cfg.MaxInstances = "http://localhost", db, time.Hour, 100
	if cfg.Logger == nil {
		cfg.Logger = slog.New(slog.NewTextHandler(io.Discard, nil))
	}
	srv, err := New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return srv
}

func get(srv http.Handler, path string, header http.Header) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodGet, path, nil)
	for k, v := range header {
		for _, vv := range v {
			r.Header.Add(k, vv)
		}
	}
	w := httptest.NewRecorder()
	srv.ServeHTTP(w, r)
	return w
}

func TestRateLimitPerClient(t *testing.T) {
	srv := newTestServer(t, Config{RateLimit: 1, RateBurst: 3, ClientIPHeader: "Fly-Client-IP"})
	now := time.Unix(1000, 0)
	srv.limiter.now = func() time.Time { return now }

	a := http.Header{"Fly-Client-IP": {"203.0.113.7"}}
	for i := range 3 {
		if w := get(srv, "/about", a); w.Code != http.StatusOK {
			t.Fatalf("request %d: status %d, want 200", i, w.Code)
		}
	}
	w := get(srv, "/about", a)
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("4th request: status %d, want 429", w.Code)
	}
	if w.Header().Get("Retry-After") != "1" {
		t.Errorf("Retry-After = %q, want 1", w.Header().Get("Retry-After"))
	}
	// Another client has its own bucket.
	if w := get(srv, "/about", http.Header{"Fly-Client-IP": {"203.0.113.8"}}); w.Code != http.StatusOK {
		t.Errorf("other client: status %d, want 200", w.Code)
	}
	// Health checks are never limited.
	if w := get(srv, "/healthz", a); w.Code != http.StatusOK {
		t.Errorf("/healthz: status %d, want 200", w.Code)
	}
	// The bucket refills.
	now = now.Add(time.Second)
	if w := get(srv, "/about", a); w.Code != http.StatusOK {
		t.Errorf("after refill: status %d, want 200", w.Code)
	}
}

func TestRateLimitIPv6Prefix(t *testing.T) {
	l := newRateLimiter(1, 1)
	l.now = func() time.Time { return time.Unix(1000, 0) }
	if ok, _ := l.allow(clientKey(netip.MustParseAddr("2001:db8::1"))); !ok {
		t.Fatal("first request refused")
	}
	if ok, _ := l.allow(clientKey(netip.MustParseAddr("2001:db8::ffff"))); ok {
		t.Error("another address in the same /64 has its own bucket")
	}
	if ok, _ := l.allow(clientKey(netip.MustParseAddr("2001:db8:0:1::1"))); !ok {
		t.Error("another /64 shares the bucket")
	}
}

func TestRateLimitSweep(t *testing.T) {
	l := newRateLimiter(10, 10)
	now := time.Unix(1000, 0)
	l.now = func() time.Time { return now }
	l.allow(clientKey(netip.MustParseAddr("192.0.2.1")))
	now = now.Add(2 * time.Minute)
	l.allow(clientKey(netip.MustParseAddr("192.0.2.2")))
	if _, ok := l.buckets[clientKey(netip.MustParseAddr("192.0.2.1"))]; ok {
		t.Error("a refilled bucket was not swept")
	}
	if len(l.buckets) != 1 {
		t.Errorf("%d buckets, want 1", len(l.buckets))
	}
}

func TestClientIPHeaderIgnoredUnlessConfigured(t *testing.T) {
	srv := newTestServer(t, Config{})
	r := httptest.NewRequest(http.MethodGet, "/", nil)
	r.RemoteAddr = "192.0.2.9:1234"
	r.Header.Set("Fly-Client-IP", "203.0.113.1")
	if got := srv.clientIP(r); got.String() != "192.0.2.9" {
		t.Errorf("clientIP = %s, want the remote address", got)
	}
}

func TestRequestLogAndMetrics(t *testing.T) {
	var logs bytes.Buffer
	srv := newTestServer(t, Config{Logger: slog.New(slog.NewTextHandler(&logs, nil))})

	get(srv, "/about", nil)
	get(srv, "/manage/wholly-blessed-mammoth", nil)
	get(srv, "/idp/no-such-thing/metadata", nil)

	out := logs.String()
	if !strings.Contains(out, "msg=request method=GET path=/about route=\"GET /about\" status=200") {
		t.Errorf("no log line for /about in:\n%s", out)
	}
	if strings.Contains(out, "wholly-blessed-mammoth") {
		t.Errorf("a management secret was logged:\n%s", out)
	}
	if !strings.Contains(out, "path=\"GET /manage/{secret}\"") {
		t.Errorf("no redacted log line for /manage in:\n%s", out)
	}

	m := get(srv.MetricsHandler(), "/metrics", nil).Body.String()
	for _, want := range []string{
		`gosaml_http_requests_total{code="200",method="GET",route="GET /about"} 1`,
		`gosaml_http_requests_total{code="404",method="GET",route="GET /idp/{id}/metadata"} 1`,
		`gosaml_http_request_duration_seconds_count{method="GET",route="GET /about"} 1`,
		`gosaml_instances 0`,
		`gosaml_live_log_subscribers 0`,
		`go_goroutines`,
	} {
		if !strings.Contains(m, want) {
			t.Errorf("metrics lack %q", want)
		}
	}
	if strings.Contains(m, "wholly-blessed-mammoth") {
		t.Error("a management secret is in a metric label")
	}
}
