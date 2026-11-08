package samlsp

import (
	"context"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// metadataServer serves IdP metadata whose SSO location is the current
// version, counting requests. While gate is set, each request waits on it.
type metadataServer struct {
	*httptest.Server
	hits    atomic.Int32
	version atomic.Int32
	fail    atomic.Bool
	gate    chan struct{}
	lastReq atomic.Pointer[http.Request]
}

func newMetadataServer(t *testing.T) *metadataServer {
	t.Helper()
	s := &metadataServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s.hits.Add(1)
		s.lastReq.Store(r)
		if s.gate != nil {
			<-s.gate
		}
		if s.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		buf, _ := xml.Marshal(testIDPMetadata(int(s.version.Load())))
		_, _ = w.Write(buf)
	}))
	t.Cleanup(s.Close)
	return s
}

func testIDPMetadata(version int) *saml.EntityDescriptor {
	return &saml.EntityDescriptor{
		EntityID: "https://idp.example.com/metadata",
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SingleSignOnServices: []saml.Endpoint{{
				Binding:  saml.HTTPRedirectBinding,
				Location: "https://idp.example.com/sso/" + strconv.Itoa(version),
			}},
		}},
	}
}

func ssoVersion(md *saml.EntityDescriptor) string {
	loc := md.IDPSSODescriptors[0].SingleSignOnServices[0].Location
	return loc[len(loc)-1:]
}

// testRemote returns a remoteMetadata for s whose clock the test sets.
func testRemote(s *metadataServer, opts ...MetadataOption) (*remoteMetadata, *time.Time) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &remoteMetadata{url: s.URL, opts: newMetadataOptions(append(opts, WithHTTPClient(s.Client())))}
	r.now = func() time.Time { return now }
	return r, &now
}

// waitIdle waits for r's fetch in progress, if any, to end.
func waitIdle(r *remoteMetadata) {
	r.mu.Lock()
	f := r.inflight
	r.mu.Unlock()
	if f != nil {
		<-f.done
	}
}

func TestRemoteMetadataCaches(t *testing.T) {
	s := newMetadataServer(t)
	r, _ := testRemote(s)
	for range 3 {
		if _, err := r.get(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("fetched %d times, want 1", n)
	}
}

func TestRemoteMetadataRefreshesInBackground(t *testing.T) {
	s := newMetadataServer(t)
	r, now := testRemote(s, WithRefreshInterval(time.Hour))
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}

	// Due for a refresh: the cached metadata comes back at once, while the
	// refresh waits at the gate.
	*now = now.Add(2 * time.Hour)
	s.version.Store(1)
	s.gate = make(chan struct{})
	md, err := r.get(t.Context())
	if err != nil || ssoVersion(md) != "0" {
		t.Fatalf("got version %s, %v; want the cached 0", ssoVersion(md), err)
	}
	// More callers neither wait nor start another fetch.
	if md, _ := r.get(t.Context()); ssoVersion(md) != "0" {
		t.Error("a second caller did not get the cached metadata")
	}
	close(s.gate)
	waitIdle(r)
	s.gate = nil

	if md, _ := r.get(t.Context()); ssoVersion(md) != "1" {
		t.Errorf("after the refresh, version %s, want 1", ssoVersion(md))
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("fetched %d times, want 2", n)
	}
}

func TestRemoteMetadataKeepsCachedOnFailure(t *testing.T) {
	s := newMetadataServer(t)
	r, now := testRemote(s, WithRefreshInterval(time.Hour))
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}
	*now = now.Add(2 * time.Hour)
	s.fail.Store(true)
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitIdle(r)
	hits := s.hits.Load()

	// Within the retry interval, no new fetch.
	*now = now.Add(30 * time.Second)
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitIdle(r)
	if s.hits.Load() != hits {
		t.Error("fetched again before the retry interval")
	}
	// After it, a retry.
	*now = now.Add(time.Minute)
	s.fail.Store(false)
	s.version.Store(1)
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}
	waitIdle(r)
	if md, _ := r.get(t.Context()); ssoVersion(md) != "1" {
		t.Errorf("version %s after the retry, want 1", ssoVersion(md))
	}
}

func TestRemoteMetadataWaitsWhenExpired(t *testing.T) {
	s := newMetadataServer(t)
	r, now := testRemote(s)
	if _, err := r.get(t.Context()); err != nil {
		t.Fatal(err)
	}
	// The cached metadata has a validUntil that has passed: callers must
	// wait for the fetch, and see its failure.
	r.mu.Lock()
	r.md.ValidUntil = now.Add(time.Minute)
	r.refreshAt = now.Add(time.Minute)
	r.mu.Unlock()
	*now = now.Add(2 * time.Minute)
	s.fail.Store(true)
	if _, err := r.get(t.Context()); err == nil {
		t.Error("expired metadata was returned")
	}
}

func TestRemoteMetadataSharesFirstFetch(t *testing.T) {
	s := newMetadataServer(t)
	s.gate = make(chan struct{})
	r, _ := testRemote(s)

	var wg sync.WaitGroup
	errs := make(chan error, 10)
	for range 10 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, err := r.get(context.Background())
			errs <- err
		}()
	}
	// Let the callers queue up, then let the one fetch through.
	for s.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	time.Sleep(10 * time.Millisecond)
	close(s.gate)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatal(err)
		}
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("fetched %d times, want 1", n)
	}
}

func TestRemoteMetadataCallerCancels(t *testing.T) {
	s := newMetadataServer(t)
	s.gate = make(chan struct{})
	r, _ := testRemote(s)

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error)
	go func() {
		_, err := r.get(ctx)
		done <- err
	}()
	for s.hits.Load() == 0 {
		time.Sleep(time.Millisecond)
	}
	cancel()
	if err := <-done; !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}
	// The fetch goes on, and its result is cached.
	close(s.gate)
	waitIdle(r)
	if _, err := r.get(t.Context()); err != nil || s.hits.Load() != 1 {
		t.Errorf("err = %v after %d fetches; the cancelled caller's fetch was lost", err, s.hits.Load())
	}
}

func TestMDQMetadata(t *testing.T) {
	s := newMetadataServer(t)
	f := MDQMetadata(s.URL+"/", "https://idp.example.com/metadata", WithHTTPClient(s.Client()))
	md, err := f(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != "https://idp.example.com/metadata" {
		t.Errorf("EntityID = %q", md.EntityID)
	}
	req := s.lastReq.Load()
	if got := req.URL.EscapedPath(); got != "/entities/https:%2F%2Fidp.example.com%2Fmetadata" {
		t.Errorf("path = %s", got)
	}
	if got := req.Header.Get("Accept"); got != "application/samlmetadata+xml" {
		t.Errorf("Accept = %q", got)
	}

	// An entity other than the one asked for is refused.
	g := MDQMetadata(s.URL, "https://other.example.com", WithHTTPClient(s.Client()))
	if _, err := g(t.Context()); err == nil {
		t.Error("metadata for another entity was accepted")
	}
}

// WithClock and WithHTTPClient work both for New and for the metadata
// functions.
var (
	_ Option         = WithClock(nil)
	_ MetadataOption = WithClock(nil)
	_ Option         = WithHTTPClient(nil)
	_ MetadataOption = WithHTTPClient(nil)
)

func TestNextRefresh(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	r := &remoteMetadata{opts: newMetadataOptions([]MetadataOption{WithRefreshInterval(time.Hour)})}
	for _, tt := range []struct {
		name string
		md   saml.EntityDescriptor
		want time.Time
	}{
		{"interval", saml.EntityDescriptor{}, now.Add(time.Hour)},
		{"shorter cacheDuration", saml.EntityDescriptor{CacheDuration: 10 * time.Minute}, now.Add(10 * time.Minute)},
		{"longer cacheDuration", saml.EntityDescriptor{CacheDuration: 3 * time.Hour}, now.Add(time.Hour)},
		{"earlier validUntil", saml.EntityDescriptor{ValidUntil: now.Add(5 * time.Minute)}, now.Add(5 * time.Minute)},
		{"later validUntil", saml.EntityDescriptor{ValidUntil: now.Add(5 * time.Hour)}, now.Add(time.Hour)},
		{"both", saml.EntityDescriptor{CacheDuration: 10 * time.Minute, ValidUntil: now.Add(5 * time.Minute)}, now.Add(5 * time.Minute)},
		// No sooner than a minute, however stale the metadata.
		{"validUntil passed", saml.EntityDescriptor{ValidUntil: now.Add(-time.Hour)}, now.Add(time.Minute)},
		{"tiny cacheDuration", saml.EntityDescriptor{CacheDuration: time.Second}, now.Add(time.Minute)},
	} {
		if got := r.nextRefresh(&tt.md, now); !got.Equal(tt.want) {
			t.Errorf("%s: %v, want %v", tt.name, got, tt.want)
		}
	}
}

// TestRemoteMetadataClock checks that WithClock decides when metadata is due
// for a refresh: metadata valid until 2001 is still fresh at a clock set to
// 2000, and due at once by the real clock.
func TestRemoteMetadataClock(t *testing.T) {
	var hits atomic.Int32
	md := testIDPMetadata(0)
	md.ValidUntil = time.Date(2001, 1, 1, 0, 0, 0, 0, time.UTC)
	buf, err := xml.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		hits.Add(1)
		_, _ = w.Write(buf)
	}))
	t.Cleanup(srv.Close)

	in2000 := RemoteMetadata(srv.URL, WithHTTPClient(srv.Client()),
		WithClock(dsig.NewFakeClockAt(time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC))))
	for range 2 {
		if _, err := in2000(t.Context()); err != nil {
			t.Fatal(err)
		}
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("with the clock in 2000: %d fetches, want 1", n)
	}

	hits.Store(0)
	now := RemoteMetadata(srv.URL, WithHTTPClient(srv.Client()))
	if _, err := now(t.Context()); err != nil {
		t.Fatal(err)
	}
	// Expired by the real clock when it arrives: it is not fetched again
	// for a minute, rather than on every call.
	if _, err := now(t.Context()); err != nil {
		t.Fatal(err)
	}
	if n := hits.Load(); n != 1 {
		t.Errorf("with the real clock: %d fetches, want 1", n)
	}
}

// TestRemoteMetadataErrorBackoff checks that, with no metadata to fall
// back on, a failed fetch is not retried for a minute: calls meanwhile get
// its error.
func TestRemoteMetadataErrorBackoff(t *testing.T) {
	s := newMetadataServer(t)
	s.fail.Store(true)
	r, now := testRemote(s)
	_, first := r.get(t.Context())
	if first == nil {
		t.Fatal("no error")
	}
	*now = now.Add(30 * time.Second)
	if _, err := r.get(t.Context()); err != first {
		t.Errorf("got %v, want the first error", err)
	}
	if n := s.hits.Load(); n != 1 {
		t.Errorf("%d fetches within the minute, want 1", n)
	}

	s.fail.Store(false)
	*now = now.Add(time.Minute)
	if _, err := r.get(t.Context()); err != nil {
		t.Errorf("after the minute: %v", err)
	}
	if n := s.hits.Load(); n != 2 {
		t.Errorf("%d fetches, want 2", n)
	}
}

func TestWithRefreshIntervalNotPositive(t *testing.T) {
	for _, d := range []time.Duration{0, -time.Minute} {
		if got := newMetadataOptions([]MetadataOption{WithRefreshInterval(d)}).refreshInterval; got != DefaultMetadataRefreshInterval {
			t.Errorf("WithRefreshInterval(%v): %v, want the default", d, got)
		}
	}
}

// TestMDQMetadataKeepsOptions checks that MDQMetadata does not write into
// the caller's slice of options.
func TestMDQMetadataKeepsOptions(t *testing.T) {
	backing := make([]MetadataOption, 2)
	backing[0] = WithRefreshInterval(time.Minute)
	MDQMetadata("https://mdq.example.com", "https://idp.example.com/metadata", backing[:1]...)
	if backing[1] != nil {
		t.Error("MDQMetadata appended to the caller's options")
	}
}

func TestRemoteMetadataFetchErrors(t *testing.T) {
	if _, err := RemoteMetadata("://bad url")(t.Context()); err == nil {
		t.Error("an invalid URL was fetched")
	}

	// Metadata that describes no IdP.
	sp := &saml.EntityDescriptor{EntityID: "https://sp.example.com", SPSSODescriptors: []saml.SPSSODescriptor{{}}}
	buf, err := xml.Marshal(sp)
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(buf) }))
	t.Cleanup(srv.Close)
	if _, err := RemoteMetadata(srv.URL, WithHTTPClient(srv.Client()))(t.Context()); err == nil {
		t.Error("metadata without an IDPSSODescriptor was accepted")
	}
}
