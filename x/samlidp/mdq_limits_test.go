package samlidp_test

import (
	"context"
	"crypto/sha1" //nolint:gosec // the MDQ transformed identifier
	"encoding/hex"
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/crewjam/saml/x/samlidp"
)

// The identifier in the URL is percent-encoded, all but the unreserved
// characters of RFC 3986 (draft-young-md-query §3), which url.PathEscape
// would leave as they are.
func TestMDQPercentEncoding(t *testing.T) {
	for _, tc := range []struct{ id, path string }{
		{"urn:x:y+z", "urn%3Ax%3Ay%2Bz"},
		{"https://sp.example.com/a?b=c&d=$e@f", "https%3A%2F%2Fsp.example.com%2Fa%3Fb%3Dc%26d%3D%24e%40f"},
		{"A-z_0.9~", "A-z_0.9~"},
		{"é ", "%C3%A9%20"},
	} {
		var got atomic.Value
		s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			got.Store(r.URL.EscapedPath())
			md := testSPMetadata(tc.id)
			md.SPSSODescriptors[0].AssertionConsumerServices[0].Location = "https://sp.example.com/acs"
			buf, _ := xml.Marshal(md)
			_, _ = w.Write(buf)
		}))
		md, err := samlidp.MDQServiceProviders(s.URL, samlidp.WithHTTPClient(s.Client()))(t.Context(), tc.id)
		s.Close()
		if err != nil {
			t.Errorf("%s: %v", tc.id, err)
			continue
		}
		if md.EntityID != tc.id {
			t.Errorf("%s: EntityID %q", tc.id, md.EntityID)
		}
		if want := "/entities/" + tc.path; got.Load() != want {
			t.Errorf("%s: path %q, want %q", tc.id, got.Load(), want)
		}
	}
}

// WithSHA1Identifiers asks for the transformed identifier (draft-young-md-query
// §2.5), and the metadata must still describe the entityID asked for.
func TestMDQSHA1Identifiers(t *testing.T) {
	const id, other = "https://sp.example.com/saml/metadata", "https://other.example.com"
	sum := sha1.Sum([]byte(id)) //nolint:gosec // the MDQ transformed identifier
	want := "/entities/%7Bsha1%7D" + hex.EncodeToString(sum[:])
	var served atomic.Value
	served.Store(id)
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.EscapedPath() != want {
			http.NotFound(w, r)
			return
		}
		buf, _ := xml.Marshal(testSPMetadata(served.Load().(string)))
		_, _ = w.Write(buf)
	}))
	t.Cleanup(s.Close)

	md, err := samlidp.MDQServiceProviders(s.URL, samlidp.WithHTTPClient(s.Client()), samlidp.WithSHA1Identifiers())(t.Context(), id)
	if err != nil || md.EntityID != id {
		t.Fatalf("got %v, %v", md, err)
	}
	served.Store(other)
	if _, err := samlidp.MDQServiceProviders(s.URL, samlidp.WithHTTPClient(s.Client()), samlidp.WithSHA1Identifiers())(t.Context(), id); err == nil {
		t.Fatal("metadata of another entity accepted")
	}
}

// At most WithMaxConcurrentFetches lookups of SPs without metadata fetch
// at once, even when their callers stop waiting; past that, an SP is
// unknown without a fetch.
func TestMDQMaxConcurrentFetches(t *testing.T) {
	release := make(chan struct{})
	var hits atomic.Int32
	s := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if strings.Contains(r.URL.Path, "slow") {
			<-release
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(s.Close)
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	sps := samlidp.MDQServiceProviders(s.URL, samlidp.WithHTTPClient(s.Client()), samlidp.WithMaxConcurrentFetches(2))

	var wg sync.WaitGroup
	for _, id := range []string{"https://slow1.example.com", "https://slow2.example.com"} {
		ctx, cancel := context.WithTimeout(t.Context(), 50*time.Millisecond)
		wg.Add(1)
		go func() {
			defer wg.Done()
			defer cancel()
			if _, err := sps(ctx, id); !errors.Is(err, context.DeadlineExceeded) {
				t.Errorf("%s: %v", id, err)
			}
		}()
	}
	wg.Wait()
	if n := hits.Load(); n != 2 {
		t.Fatalf("%d fetches", n)
	}

	// The two fetches go on, though their callers stopped waiting.
	if _, err := sps(t.Context(), "https://third.example.com"); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Fatalf("third: %v", err)
	}
	if n := hits.Load(); n != 2 {
		t.Fatalf("%d fetches, want 2", n)
	}

	once.Do(func() { close(release) })
	deadline := time.Now().Add(5 * time.Second)
	for {
		_, err := sps(t.Context(), "https://third.example.com")
		if !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
			t.Fatalf("third: %v", err)
		}
		if hits.Load() == 3 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the fetches were not let go")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

// Failed lookups do not push the metadata of a known SP out of the cache.
func TestMDQFailedLookupsKeptApart(t *testing.T) {
	a := testSPMetadata("https://a.example.com")
	s := newMDQServer(t, a)
	sps := samlidp.MDQServiceProviders(s.URL+"/mdq", samlidp.WithHTTPClient(s.Client()), samlidp.WithMaxCachedServiceProviders(1))
	if _, err := sps(t.Context(), a.EntityID); err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"https://junk1.example.com", "https://junk2.example.com", "https://junk3.example.com"} {
		if _, err := sps(t.Context(), id); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
			t.Fatalf("%s: %v", id, err)
		}
	}
	if _, err := sps(t.Context(), a.EntityID); err != nil {
		t.Fatal(err)
	}
	if n := s.hits.Load(); n != 4 {
		t.Errorf("fetched %d times, want 4: the known SP was fetched again", n)
	}
}
