package main

import (
	"crypto/rand"
	"crypto/x509"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// testSP is a service provider of x/samlsp, with single logout, that logs
// users in with the example IdP.
type testSP struct {
	server *httptest.Server
	config *samlsp.Config
	logout *slo.Service

	mu      sync.Mutex
	pending map[string]string // request ID by RelayState
	user    *samlsp.Assertion
}

func newTestSP(t *testing.T, idpMetadata samlsp.MetadataFunc) *testSP {
	t.Helper()
	sp := &testSP{pending: map[string]string{}}
	mux := http.NewServeMux()
	sp.server = httptest.NewServer(mux)
	t.Cleanup(sp.server.Close)

	key, cert, err := newKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	base := sp.server.URL
	if sp.config, err = samlsp.New(base+"/saml/metadata", idpMetadata,
		samlsp.WithSigningKey(key, cert), slo.Endpoint(base+"/saml/slo")); err != nil {
		t.Fatal(err)
	}
	if sp.logout, err = slo.New(sp.config); err != nil {
		t.Fatal(err)
	}

	mux.HandleFunc(sp.config.MetadataPath(), sp.config.ServeMetadata)
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		relayState := rand.Text()
		msg, err := sp.config.AuthnRequest(r.Context(), relayState)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sp.mu.Lock()
		sp.pending[relayState] = msg.ID
		sp.mu.Unlock()
		msg.Write(w)
	})
	mux.HandleFunc(sp.config.ACSPath(), func(w http.ResponseWriter, r *http.Request) {
		sp.mu.Lock()
		id := sp.pending[r.FormValue("RelayState")]
		sp.mu.Unlock()
		// Accept IdP-initiated logins too, from the IdP's portal.
		a, err := sp.config.ParseResponse(r.Context(), r, samlsp.WithRequestID(id), samlsp.AllowUnsolicited)
		if err != nil {
			http.Error(w, "login failed", http.StatusForbidden)
			return
		}
		sp.mu.Lock()
		sp.user = a
		sp.mu.Unlock()
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		_, _ = fmt.Fprintf(w, "hello %s", a.Attributes.Get("urn:oid:0.9.2342.19200300.100.1.1")) //nolint:gosec // G705: text/plain
	})
	mux.HandleFunc("/logout", func(w http.ResponseWriter, r *http.Request) {
		sp.mu.Lock()
		a := sp.user
		sp.user = nil
		sp.mu.Unlock()
		relayState := rand.Text()
		msg, err := sp.logout.Request(r.Context(), a.NameID, relayState, slo.WithSessionIndex(a.SessionIndexes...))
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		sp.mu.Lock()
		sp.pending[relayState] = msg.ID
		sp.mu.Unlock()
		msg.Write(w)
	})
	mux.HandleFunc(sp.logout.Path(), func(w http.ResponseWriter, r *http.Request) {
		switch {
		case slo.IsRequest(r):
			req, err := sp.logout.ParseRequest(r.Context(), r)
			if err != nil {
				slo.WriteRequestError(w, r)
				return
			}
			sp.mu.Lock()
			sp.user = nil
			sp.mu.Unlock()
			msg, err := sp.logout.Response(r.Context(), req)
			if err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			msg.Write(w)
		case slo.IsResponse(r):
			sp.mu.Lock()
			id := sp.pending[r.FormValue("RelayState")]
			sp.mu.Unlock()
			if _, err := sp.logout.ParseResponse(r.Context(), r, id); err != nil {
				http.Error(w, "logout failed", http.StatusForbidden)
				return
			}
			_, _ = io.WriteString(w, "logged out")
		}
	})
	return sp
}

func (sp *testSP) loggedIn() *samlsp.Assertion {
	sp.mu.Lock()
	defer sp.mu.Unlock()
	return sp.user
}

// browser follows redirects and submits the self-submitting forms of the
// SAML POST bindings, as a browser with JavaScript does.
type browser struct {
	t      *testing.T
	client *http.Client
}

func newBrowser(t *testing.T) *browser {
	jar, err := cookiejar.New(nil)
	if err != nil {
		t.Fatal(err)
	}
	return &browser{t: t, client: &http.Client{Jar: jar}}
}

var (
	formRE  = regexp.MustCompile(`<form method="post" action="([^"]*)" id="SAMLForm">`)
	inputRE = regexp.MustCompile(`<input type="hidden" name="([^"]*)" value="([^"]*)"`)
)

// page is where the browser ends up: the status, URL and body of the last
// response.
type page struct {
	status int
	url    *url.URL
	body   string
}

// do sends r and returns the page the browser ends up on.
func (b *browser) do(r *http.Request) page {
	b.t.Helper()
	for range 20 {
		resp, err := b.client.Do(r)
		if err != nil {
			b.t.Fatal(err)
		}
		body, err := io.ReadAll(resp.Body)
		_ = resp.Body.Close()
		if err != nil {
			b.t.Fatal(err)
		}
		m := formRE.FindStringSubmatch(string(body))
		if m == nil {
			return page{resp.StatusCode, resp.Request.URL, string(body)}
		}
		r = postForm(html.UnescapeString(m[1]), formFields(string(body)))
	}
	b.t.Fatal("too many forms")
	return page{}
}

func (b *browser) get(u string) page {
	b.t.Helper()
	r, err := http.NewRequest(http.MethodGet, u, http.NoBody)
	if err != nil {
		b.t.Fatal(err)
	}
	return b.do(r)
}

func (b *browser) post(u string, fields url.Values) page {
	b.t.Helper()
	return b.do(postForm(u, fields))
}

func postForm(u string, fields url.Values) *http.Request {
	r, _ := http.NewRequest(http.MethodPost, u, strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

func formFields(body string) url.Values {
	fields := url.Values{}
	for _, m := range inputRE.FindAllStringSubmatch(body, -1) {
		fields.Add(html.UnescapeString(m[1]), html.UnescapeString(m[2]))
	}
	return fields
}

// world is the example IdP and a service provider that trusts it.
type world struct {
	idp  *identityProvider
	url  string
	cert *x509.Certificate // signs the IdP metadata
	sp   *testSP
}

func newWorld(t *testing.T) *world {
	t.Helper()
	w := &world{}
	mux := http.NewServeMux()
	server := httptest.NewServer(mux)
	t.Cleanup(server.Close)
	w.url = server.URL

	key, cert, err := newKeyPair()
	if err != nil {
		t.Fatal(err)
	}
	w.cert = cert
	// The metadata is served over plain http, so it is trusted for its
	// signature.
	// The IdP is on loopback, which the library's default client refuses.
	w.sp = newTestSP(t, samlsp.RemoteMetadata(server.URL+"/metadata", samlsp.WithMetadataSigners(cert), samlsp.WithHTTPClient(server.Client()),
		samlsp.WithIdentityProviderEntityID(server.URL+"/metadata")))
	sps := newRemoteServiceProviders([]string{w.sp.config.EntityID()}, nil)
	if w.idp, err = newIdentityProvider(server.URL, key, cert, sps, exampleUsers()); err != nil {
		t.Fatal(err)
	}
	mux.Handle("/", w.idp.handler())
	return w
}

// logIn fills in the login form on page, of the IdP at idpURL, with user
// and password.
func (b *browser) logIn(idpURL string, form page, user, password string) page {
	b.t.Helper()
	fields := formFields(form.body)
	if fields.Get("csrf") == "" || !strings.Contains(form.body, `<form method="post" action="/login">`) {
		b.t.Fatalf("not a login form: %s", form.body)
	}
	fields.Set("user", user)
	fields.Set("password", password)
	return b.post(idpURL+"/login", fields)
}

func TestLoginAndLogout(t *testing.T) {
	w := newWorld(t)
	b := newBrowser(t)

	// The SP sends the browser to the IdP, which asks the user to log in.
	p := b.get(w.sp.server.URL + "/login")
	if !strings.Contains(p.body, "Log in") {
		t.Fatalf("no login form: %s", p.body)
	}
	p = b.logIn(w.url, p, "alice", "wrong")
	if !strings.Contains(p.body, "Wrong username or password") {
		t.Fatalf("wrong password: %s", p.body)
	}
	p = b.logIn(w.url, p, "alice", "hunter2")
	if p.body != "hello alice" || p.url.Host != mustHost(t, w.sp.server.URL) {
		t.Fatalf("got %s at %s", p.body, p.url)
	}
	a := w.sp.loggedIn()
	if a.Attributes.Get("urn:oid:0.9.2342.19200300.100.1.3") != "alice@example.com" || len(a.Attributes.Values("urn:oid:1.3.6.1.4.1.5923.1.5.1.1")) != 2 {
		t.Fatalf("attributes %+v", a.Attributes)
	}

	// The IdP session logs the user in again without the form.
	if p = b.get(w.sp.server.URL + "/login"); p.body != "hello alice" {
		t.Fatalf("second login: %s", p.body)
	}
	if p = b.get(w.url + "/"); !strings.Contains(p.body, "Logged in as alice") || !strings.Contains(p.body, w.sp.config.EntityID()) {
		t.Fatalf("portal: %s", p.body)
	}

	// The SP starts single logout; the IdP ends its session and answers.
	if p = b.get(w.sp.server.URL + "/logout"); p.body != "logged out" {
		t.Fatalf("SP-initiated logout: %s", p.body)
	}
	if p = b.get(w.url + "/"); !strings.Contains(p.body, "Not logged in") {
		t.Fatalf("portal after logout: %s", p.body)
	}

	// Log in from the portal: an IdP-initiated login.
	p = b.get(w.url + "/login")
	if p = b.logIn(w.url, p, "bob", "hunter2"); !strings.Contains(p.body, "Logged in as bob") {
		t.Fatalf("login at the portal: %s", p.body)
	}
	if p = b.post(w.url+"/idp-initiated", url.Values{"sp": {w.sp.config.EntityID()}}); p.body != "hello bob" {
		t.Fatalf("IdP-initiated login: %s", p.body)
	}

	// Log out of everything from the portal: the IdP visits the SP.
	p = b.post(w.url+"/logout", nil)
	if !strings.Contains(p.body, "Not logged in") || w.sp.loggedIn() != nil {
		t.Fatalf("IdP-initiated logout ended at %s: %s (SP user %v)", p.url, p.body, w.sp.loggedIn())
	}
}

func TestLoginCSRF(t *testing.T) {
	w := newWorld(t)
	b := newBrowser(t)
	p := b.post(w.url+"/login", url.Values{"user": {"alice"}, "password": {"hunter2"}, "csrf": {"forged"}})
	if p.status != http.StatusForbidden {
		t.Fatalf("got %d", p.status)
	}
}

func TestUntrustedSP(t *testing.T) {
	w := newWorld(t)
	other := newTestSP(t, samlsp.RemoteMetadata(w.url+"/metadata", samlsp.WithMetadataSigners(w.cert), samlsp.WithHTTPClient(http.DefaultClient),
		samlsp.WithIdentityProviderEntityID(w.url+"/metadata")))
	b := newBrowser(t)
	if p := b.get(other.server.URL + "/login"); p.status != http.StatusBadRequest {
		t.Fatalf("got %d", p.status)
	}
	if p := b.post(w.url+"/idp-initiated", url.Values{"sp": {other.config.EntityID()}}); p.status != http.StatusBadRequest {
		t.Fatalf("IdP-initiated: got %d", p.status)
	}
}

func mustHost(t *testing.T, s string) string {
	t.Helper()
	u, err := url.Parse(s)
	if err != nil {
		t.Fatal(err)
	}
	return u.Host
}
