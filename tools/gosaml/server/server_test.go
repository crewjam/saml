package server

import (
	"html"
	"io"
	"log/slog"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml/tools/gosaml/store"
)

type harness struct {
	t      *testing.T
	base   string
	client *http.Client
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	db, err := store.Open(":memory:")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })

	var handler http.Handler
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { handler.ServeHTTP(w, r) }))
	t.Cleanup(ts.Close)
	srv, err := New(Config{
		BaseURL: ts.URL, Store: db, TTL: time.Hour, MaxInstances: 100,
		Logger: slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	if err != nil {
		t.Fatal(err)
	}
	handler = srv
	jar, _ := cookiejar.New(nil)
	return &harness{t: t, base: ts.URL, client: &http.Client{Jar: jar}}
}

// newBrowser returns a harness for the same server with its own cookies.
func (h *harness) newBrowser() *harness {
	jar, _ := cookiejar.New(nil)
	return &harness{t: h.t, base: h.base, client: &http.Client{Jar: jar}}
}

func (h *harness) do(method, path string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	target := path
	if strings.HasPrefix(path, "/") {
		target = h.base + path
	}
	var resp *http.Response
	var err error
	if method == http.MethodPost {
		resp, err = h.client.PostForm(target, form)
	} else {
		resp, err = h.client.Get(target)
	}
	if err != nil {
		h.t.Fatal(err)
	}
	defer resp.Body.Close() //nolint:errcheck // test
	b, _ := io.ReadAll(resp.Body)
	return resp, string(b)
}

var (
	formRe   = regexp.MustCompile(`(?s)<form[^>]*method="post"[^>]*action="([^"]+)"[^>]*>(.*?)</form>`)
	hiddenRe = regexp.MustCompile(`<input type="hidden" name="([^"]+)" value="([^"]*)"`)
)

// submitAutoForm submits the self-submitting SAML form in body, as the
// browser's script would.
func (h *harness) submitAutoForm(body string) (*http.Response, string) {
	h.t.Helper()
	m := formRe.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("no form in:\n%s", body)
	}
	form := url.Values{}
	for _, in := range hiddenRe.FindAllStringSubmatch(m[2], -1) {
		form.Set(in[1], html.UnescapeString(in[2]))
	}
	return h.do(http.MethodPost, html.UnescapeString(m[1]), form)
}

func (h *harness) create(kind string) (secret, id string) {
	h.t.Helper()
	resp, body := h.do(http.MethodPost, "/new/"+kind, nil)
	secret = strings.TrimPrefix(resp.Request.URL.Path, "/manage/")
	m := regexp.MustCompile(`/` + kind + `/([a-z0-9-]+)/metadata`).FindStringSubmatch(body)
	if resp.StatusCode != http.StatusOK || m == nil {
		h.t.Fatalf("create %s: %d\n%s", kind, resp.StatusCode, body)
	}
	return secret, m[1]
}

func mustContain(t *testing.T, body string, want ...string) {
	t.Helper()
	for _, w := range want {
		if !strings.Contains(body, w) {
			t.Fatalf("missing %q in:\n%s", w, body)
		}
	}
}

var pendingRe = regexp.MustCompile(`name="pending" value="([^"]+)"`)

// loginAt answers the IdP login page in body.
func (h *harness) loginAt(idpID, body string, form url.Values) (*http.Response, string) {
	h.t.Helper()
	m := pendingRe.FindStringSubmatch(body)
	if m == nil {
		h.t.Fatalf("no login page:\n%s", body)
	}
	form.Set("pending", m[1])
	return h.do(http.MethodPost, "/idp/"+idpID+"/login", form)
}

func TestEndToEnd(t *testing.T) {
	h := newHarness(t)

	for _, p := range []string{"/", "/inspect", "/about", "/healthz", "/static/style.css"} {
		if resp, body := h.do(http.MethodGet, p, nil); resp.StatusCode != http.StatusOK {
			t.Fatalf("%s: %d\n%s", p, resp.StatusCode, body)
		}
	}

	idpSecret, idpID := h.create("idp")
	spSecret, spID := h.create("sp")

	// The home page lists both, for this browser.
	_, body := h.do(http.MethodGet, "/", nil)
	mustContain(t, body, "/manage/"+idpSecret, "/manage/"+spSecret)

	// Point the SP at the IdP. Its metadata URL is answered locally.
	_, body = h.do(http.MethodPost, "/manage/"+spSecret+"/idp-set", url.Values{"metadata_url": {h.base + "/idp/" + idpID + "/metadata"}})
	mustContain(t, body, "Identity provider "+h.base+"/idp/"+idpID+"/metadata saved")

	// SP-initiated login. The IdP fetches the unregistered SP's metadata
	// from its entity ID.
	resp, body := h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"force_authn": {"on"}})
	if resp.Request.URL.Path != "/idp/"+idpID+"/sso" {
		t.Fatalf("login went to %s:\n%s", resp.Request.URL, body)
	}
	mustContain(t, body, "Log in as", "alice", "ForceAuthn")
	_, body = h.loginAt(idpID, body, url.Values{"user": {"alice"}, "action": {"login"}})
	acsPage := body
	_, body = h.submitAutoForm(acsPage)
	mustContain(t, body, "Logged in as", "alice@example.com", "urn:oid:0.9.2342.19200300.100.1.3", "admins", "Manage this SP")

	// The same Response again is refused: the login it answers is over.
	resp, body = h.submitAutoForm(acsPage)
	if resp.StatusCode != http.StatusForbidden {
		t.Fatalf("replay: %d", resp.StatusCode)
	}
	mustContain(t, body, "Login refused", "already completed")

	// The IdP session answers the next login without asking (single
	// sign-on), and so an IsPassive one.
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"is_passive": {"on"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "Logged in as", "alice@example.com")

	// A browser without an IdP session gets NoPassive.
	other := h.newBrowser()
	_, body = other.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"is_passive": {"on"}})
	_, body = other.submitAutoForm(body)
	mustContain(t, body, "Login refused", "NoPassive")

	// An error Response. ForceAuthn shows the login page despite the
	// session.
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"force_authn": {"on"}})
	_, body = h.loginAt(idpID, body, url.Values{"action": {"error"}, "error_status": {"AuthnFailed"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "Login refused", "AuthnFailed")

	// A transient NameID, over HTTP-POST.
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"binding": {"post"}, "force_authn": {"on"}})
	_, body = h.submitAutoForm(body) // the AuthnRequest form
	_, body = h.loginAt(idpID, body, url.Values{"user": {"bob"}, "action": {"login"}, "nameid_format": {"urn:oasis:names:tc:SAML:2.0:nameid-format:transient"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "Logged in as", "nameid-format:transient")

	// IdP-initiated login.
	_, body = h.do(http.MethodPost, "/manage/"+idpSecret+"/initiate", url.Values{"entity_id": {h.base + "/sp/" + spID + "/metadata"}, "relay_state": {"/after"}})
	_, body = h.loginAt(idpID, body, url.Values{"user": {"carol"}, "action": {"login"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "Logged in as", "carol@example.com", "IdP-initiated", "/after")

	// The logs recorded the messages, decoded.
	_, body = h.do(http.MethodGet, "/manage/"+idpSecret, nil)
	mustContain(t, body, "AuthnRequest from", "Response to")
	mustContain(t, h.logEntries(idpSecret), "samlp:AuthnRequest", "HTTP request", "GET /idp/"+idpID+"/sso?SAMLRequest=")
	_, body = h.do(http.MethodGet, "/manage/"+spSecret, nil)
	mustContain(t, body, "AuthnRequest to", "Logged in alice@example.com", "Response refused")

	// Users can be edited.
	_, body = h.do(http.MethodPost, "/manage/"+idpSecret+"/user-save", url.Values{
		"username": {"dave"}, "nameid": {"dave-1"}, "nameid_format": {"urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
		"attributes": {"role (Role) = a\nrole = b\n"},
	})
	mustContain(t, body, "User dave saved")
	_, body = h.do(http.MethodPost, "/sp/"+spID+"/login", url.Values{"force_authn": {"on"}})
	_, body = h.loginAt(idpID, body, url.Values{"user": {"dave"}, "action": {"login"}})
	_, body = h.submitAutoForm(body)
	mustContain(t, body, "dave-1", "Role")

	// Another browser sees neither the instances nor the manage link.
	other = h.newBrowser()
	_, body = other.do(http.MethodGet, "/", nil)
	if strings.Contains(body, idpSecret) {
		t.Error("another browser sees the IdP")
	}

	// Deleting an instance removes it.
	h.do(http.MethodPost, "/manage/"+spSecret+"/delete", nil)
	if resp, _ := h.do(http.MethodGet, "/sp/"+spID+"/metadata", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("deleted SP metadata: %d", resp.StatusCode)
	}
}

func TestGuard(t *testing.T) {
	for addr, ok := range map[string]bool{
		"127.0.0.1:443":              false,
		"10.1.2.3:443":               false,
		"169.254.169.254:80":         false,
		"[fdaa::3]:443":              false,
		"[::1]:443":                  false,
		"100.64.1.1:443":             false,
		"8.8.8.8:443":                true,
		"8.8.8.8:22":                 false,
		"[2606:4700::1111]:80":       true,
		"[64:ff9b::a00:1]:443":       false, // NAT64 of 10.0.0.1
		"[64:ff9b:1::a9fe:a9fe]:443": false, // local NAT64 of 169.254.169.254
		"[2002:a00:1::1]:443":        false, // 6to4 of 10.0.0.1
		"[2001:0:4136:e378:8000:63bf:f5ff:fffe]:443": false, // Teredo
		"[::ffff:10.0.0.1]:443":                      false,
		"0.0.0.0:443":                                false,
	} {
		network := "tcp4"
		if strings.HasPrefix(addr, "[") {
			network = "tcp6"
		}
		if err := guard.Safe(network, addr, nil); (err == nil) != ok {
			t.Errorf("%s: %v", addr, err)
		}
	}
}

func TestParseAttributes(t *testing.T) {
	attrs, err := parseAttributes("# comment\nurn:oid:1 (mail) = a@b\ngroups = x\ngroups = y = z\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(attrs) != 2 || attrs[0].FriendlyName != "mail" || attrs[0].NameFormat == "" ||
		len(attrs[1].Values) != 2 || attrs[1].Values[1] != "y = z" {
		t.Fatalf("%+v", attrs)
	}
	if got := formatAttributes(attrs); got != "urn:oid:1 (mail) = a@b\ngroups = x\ngroups = y = z\n" {
		t.Errorf("format: %q", got)
	}
	if _, err := parseAttributes("novalue"); err == nil {
		t.Error("expected an error")
	}
}

// Boosted form posts are answered with HX-Location, keeping the
// fragment a redirect would lose, and never push a POST URL.
func TestBoostedPost(t *testing.T) {
	h := newHarness(t)
	secret, _ := h.create("sp")
	req, _ := http.NewRequest(http.MethodPost, h.base+"/manage/"+secret+"/idp-set", strings.NewReader("metadata_xml=nonsense"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("HX-Request", "true")
	resp, err := h.client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close() //nolint:errcheck // test
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(resp.Header.Get("HX-Location"), "/manage/"+secret+"?msg=") || !strings.HasSuffix(resp.Header.Get("HX-Location"), "#idp") {
		t.Fatalf("got %d, HX-Location %q", resp.StatusCode, resp.Header.Get("HX-Location"))
	}
	if resp.Header.Get("HX-Push-Url") != "false" {
		t.Fatalf("HX-Push-Url = %q", resp.Header.Get("HX-Push-Url"))
	}
	// Without htmx, it is an ordinary redirect.
	resp, _ = h.do(http.MethodPost, "/manage/"+secret+"/clear-events", url.Values{})
	if resp.Request.URL.Path != "/manage/"+secret {
		t.Fatalf("not redirected: %s", resp.Request.URL)
	}
}
