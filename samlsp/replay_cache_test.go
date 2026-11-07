package samlsp

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

var replayCacheTestNow = time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)

// setReplayCacheTestNow makes saml.TimeNow return *now for the rest of the
// test.
func setReplayCacheTestNow(t *testing.T, now *time.Time) {
	t.Helper()
	oldTimeNow := saml.TimeNow
	t.Cleanup(func() { saml.TimeNow = oldTimeNow })
	saml.TimeNow = func() time.Time { return *now }
}

func TestMemoryReplayCacheRefusesReplay(t *testing.T) {
	now := replayCacheTestNow
	setReplayCacheTestNow(t, &now)
	c := NewMemoryReplayCache(10)

	assert.NilError(t, c.Consume("id-1", now.Add(time.Minute)))
	assert.Check(t, is.ErrorIs(c.Consume("id-1", now.Add(time.Minute)), saml.ErrAssertionReplayed))
	assert.Check(t, c.Consume("id-2", now.Add(time.Minute)))

	// Still refused up to the recorded expiry, accepted from then on.
	now = now.Add(time.Minute - time.Nanosecond)
	assert.Check(t, is.ErrorIs(c.Consume("id-1", now.Add(time.Minute)), saml.ErrAssertionReplayed))
	now = now.Add(time.Nanosecond)
	assert.Check(t, c.Consume("id-1", now.Add(time.Minute)))
	assert.Check(t, is.ErrorIs(c.Consume("id-1", now.Add(time.Minute)), saml.ErrAssertionReplayed))
}

// A full cache refuses new IDs instead of dropping an unexpired one, and
// accepts them again once IDs have expired.
func TestMemoryReplayCacheFull(t *testing.T) {
	now := replayCacheTestNow
	setReplayCacheTestNow(t, &now)
	c := NewMemoryReplayCache(2)

	assert.NilError(t, c.Consume("id-1", now.Add(time.Minute)))
	assert.NilError(t, c.Consume("id-2", now.Add(2*time.Minute)))
	assert.Check(t, is.ErrorIs(c.Consume("id-3", now.Add(time.Minute)), ErrReplayCacheFull))
	assert.Check(t, is.Len(c.entries, 2))

	// The recorded IDs are still refused as replays, not as a full cache.
	assert.Check(t, is.ErrorIs(c.Consume("id-1", now.Add(time.Minute)), saml.ErrAssertionReplayed))
	assert.Check(t, is.ErrorIs(c.Consume("id-2", now.Add(time.Minute)), saml.ErrAssertionReplayed))

	// Once id-1 expires there is room for one more.
	now = now.Add(time.Minute)
	assert.Check(t, c.Consume("id-3", now.Add(time.Minute)))
	assert.Check(t, is.ErrorIs(c.Consume("id-4", now.Add(time.Minute)), ErrReplayCacheFull))
	assert.Check(t, is.ErrorIs(c.Consume("id-2", now.Add(time.Minute)), saml.ErrAssertionReplayed))
	assert.Check(t, is.ErrorIs(c.Consume("id-3", now.Add(time.Minute)), saml.ErrAssertionReplayed))

	// Once everything expires the cache is emptied as it fills again.
	now = now.Add(time.Hour)
	assert.Check(t, c.Consume("id-4", now.Add(time.Minute)))
	assert.Check(t, c.Consume("id-5", now.Add(time.Minute)))
	assert.Check(t, is.Len(c.entries, 2))
}

// An ID recorded with an expiry that has already passed takes no room.
func TestMemoryReplayCacheAlreadyExpired(t *testing.T) {
	now := replayCacheTestNow
	setReplayCacheTestNow(t, &now)
	c := NewMemoryReplayCache(1)

	assert.NilError(t, c.Consume("id-1", now))
	assert.Check(t, c.Consume("id-2", now.Add(time.Minute)))
	assert.Check(t, is.Len(c.entries, 1))
}

func TestNewMemoryReplayCacheRequiresPositiveSize(t *testing.T) {
	for _, n := range []int{0, -1} {
		func() {
			defer func() {
				assert.Check(t, recover() != nil, "NewMemoryReplayCache(%d) did not panic", n)
			}()
			NewMemoryReplayCache(n)
		}()
	}
}

func TestMemoryReplayCacheConcurrentSameID(t *testing.T) {
	now := replayCacheTestNow
	setReplayCacheTestNow(t, &now)
	c := NewMemoryReplayCache(10)

	const workers = 50
	var accepted, replayed atomic.Int32
	var wg sync.WaitGroup
	for range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.Consume("id-1", now.Add(time.Minute))
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, saml.ErrAssertionReplayed):
				replayed.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Check(t, is.Equal(int32(1), accepted.Load()))
	assert.Check(t, is.Equal(int32(workers-1), replayed.Load()))
}

func TestMemoryReplayCacheConcurrentDistinctIDs(t *testing.T) {
	now := replayCacheTestNow
	setReplayCacheTestNow(t, &now)
	const maxEntries, workers = 20, 100
	c := NewMemoryReplayCache(maxEntries)

	var accepted, full atomic.Int32
	var wg sync.WaitGroup
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := c.Consume(fmt.Sprintf("id-%d", i), now.Add(time.Minute))
			switch {
			case err == nil:
				accepted.Add(1)
			case errors.Is(err, ErrReplayCacheFull):
				full.Add(1)
			}
		}()
	}
	wg.Wait()
	assert.Check(t, is.Equal(int32(maxEntries), accepted.Load()))
	assert.Check(t, is.Equal(int32(workers-maxEntries), full.Load()))
	assert.Check(t, is.Len(c.entries, maxEntries))
}

func TestNewPassesReplayCache(t *testing.T) {
	cache := NewMemoryReplayCache(1)
	m, err := New(Options{URL: mustParseURL("https://sp.example.com/"), ReplayCache: cache})
	assert.NilError(t, err)
	assert.Check(t, m.ServiceProvider.ReplayCache == saml.AssertionReplayCache(cache))

	m, err = New(Options{URL: mustParseURL("https://sp.example.com/")})
	assert.NilError(t, err)
	assert.Check(t, is.Nil(m.ServiceProvider.ReplayCache))
}

// With Options.ReplayCache set, the ACS accepts a response once and refuses
// the same response again.
func TestMiddlewareRefusesReplayedResponse(t *testing.T) {
	test := NewMiddlewareTest(t)
	m, err := New(Options{
		URL:         mustParseURL("https://15661444.ngrok.io/"),
		Key:         test.Key,
		Certificate: test.Certificate,
		IDPMetadata: test.Middleware.ServiceProvider.IDPMetadata,
		ReplayCache: NewMemoryReplayCache(10),
	})
	assert.NilError(t, err)
	m.ServiceProvider.MetadataURL.Path = "/saml2/metadata"
	m.ServiceProvider.AcsURL.Path = "/saml2/acs"
	m.ServiceProvider.SloURL.Path = "/saml2/slo"
	test.Middleware = m

	post := func() int {
		v := url.Values{}
		v.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
		v.Set("RelayState", "KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6")
		req, _ := http.NewRequest("POST", "/saml2/acs", bytes.NewReader([]byte(v.Encode())))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Cookie", ""+
			"saml_KCosLjAyNDY4Ojw-QEJERkhKTE5QUlRWWFpcXmBiZGZoamxucHJ0dnh6="+test.makeTrackedRequest("id-9e61753d64e928af5a7a341a97f420c9"))
		resp := httptest.NewRecorder()
		m.ServeHTTP(resp, req)
		return resp.Code
	}

	assert.Check(t, is.Equal(http.StatusFound, post()))
	assert.Check(t, is.Equal(http.StatusForbidden, post()))
}
