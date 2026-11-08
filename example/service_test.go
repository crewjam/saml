package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

func requestAs(method, body, account string) *http.Request {
	r := httptest.NewRequest(method, "/", strings.NewReader(body))
	if body != "" {
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	if account != "" {
		r = r.WithContext(contextWithSession(r.Context(), &session{assertion: &samlsp.Assertion{Subject: account}}))
	}
	return r
}

func resetLinks(t *testing.T) {
	t.Helper()
	links.mu.Lock()
	links.links = map[string]Link{}
	links.mu.Unlock()
}

func createLink(t *testing.T, target, account string) string {
	t.Helper()
	w := httptest.NewRecorder()
	CreateLink(w, requestAs(http.MethodPost, url.Values{"t": {target}}.Encode(), account))
	if w.Code != http.StatusOK {
		t.Fatalf("CreateLink(%q) = %d %q", target, w.Code, w.Body.String())
	}
	return strings.TrimSpace(w.Body.String())
}

func TestCreateLinkStoresTargetAndOwner(t *testing.T) {
	resetLinks(t)

	a := createLink(t, "https://example.com/a", "alice@example.com")
	b := createLink(t, "https://example.com/b", "alice@example.com")
	if a == b {
		t.Fatalf("two links got the same short name %q", a)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /{link}", ServeLink)
	for short, want := range map[string]string{a: "https://example.com/a", b: "https://example.com/b"} {
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/"+short, nil))
		if got := w.Header().Get("Location"); w.Code != http.StatusFound || got != want {
			t.Errorf("GET /%s = %d Location %q, want 302 %q", short, w.Code, got, want)
		}
	}
}

func TestListLinksUsesSessionNotHeader(t *testing.T) {
	resetLinks(t)
	short := createLink(t, "https://example.com/", "alice@example.com")

	w := httptest.NewRecorder()
	r := requestAs(http.MethodGet, "", "bob@example.com")
	r.Header.Set("X-Remote-User", "alice@example.com")
	ListLinks(w, r)
	if strings.Contains(w.Body.String(), short) {
		t.Errorf("bob sees alice's link by setting X-Remote-User: %q", w.Body.String())
	}

	w = httptest.NewRecorder()
	ListLinks(w, requestAs(http.MethodGet, "", "alice@example.com"))
	if strings.TrimSpace(w.Body.String()) != short {
		t.Errorf("alice's links = %q, want %q", w.Body.String(), short)
	}
}

func TestCreateLinkRejectsBadRequests(t *testing.T) {
	resetLinks(t)
	for _, tc := range []struct {
		name, target, account string
		want                  int
	}{
		{"no session", "https://example.com/", "", http.StatusForbidden},
		{"empty target", "", "alice", http.StatusBadRequest},
		{"relative target", "/foo", "alice", http.StatusBadRequest},
		{"javascript target", "javascript:alert(1)", "alice", http.StatusBadRequest},
	} {
		t.Run(tc.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			CreateLink(w, requestAs(http.MethodPost, url.Values{"t": {tc.target}}.Encode(), tc.account))
			if w.Code != tc.want {
				t.Errorf("got %d, want %d", w.Code, tc.want)
			}
		})
	}
}

func TestLinksConcurrentAccess(t *testing.T) {
	resetLinks(t)
	var wg sync.WaitGroup
	for i := 0; i < 20; i++ {
		wg.Add(2)
		go func() {
			defer wg.Done()
			createLink(t, "https://example.com/", "alice")
		}()
		go func() {
			defer wg.Done()
			ListLinks(httptest.NewRecorder(), requestAs(http.MethodGet, "", "alice"))
		}()
	}
	wg.Wait()
}

func TestIsLocalURL(t *testing.T) {
	for p, want := range map[string]bool{
		"/": true, "/links?x=1": true,
		"": false, "https://evil.example": false, "//evil.example": false, `/\evil.example`: false, "evil": false, "/\t/evil.example": false, "/\n/evil.example": false,
	} {
		if got := isLocalURL(p); got != want {
			t.Errorf("isLocalURL(%q) = %v, want %v", p, got, want)
		}
	}
}
