package samlsp_test

import (
	"bytes"
	"compress/flate"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func newKeyPair(t *testing.T, cn string) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: cn},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// testIDP is an in-process identity provider with one logged-in user.
type testIDP struct {
	idp       *saml.IdentityProvider
	key       *rsa.PrivateKey
	cert      *x509.Certificate
	spMeta    *saml.EntityDescriptor
	loggedOut bool
}

func (ti *testIDP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if ti.spMeta != nil && id == ti.spMeta.EntityID {
		return ti.spMeta, nil
	}
	return nil, errors.New("unknown service provider")
}

func (ti *testIDP) GetSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpAuthnRequest) *saml.Session {
	return &saml.Session{
		ID:           "session-1",
		Index:        "index-1",
		CreateTime:   time.Now(),
		ExpireTime:   time.Now().Add(time.Hour),
		NameID:       "alice@example.com",
		NameIDFormat: string(saml.EmailAddressNameIDFormat),
		UserName:     "alice",
		UserEmail:    "alice@example.com",
		Groups:       []string{"admins", "users"},
	}
}

func (ti *testIDP) InvalidateSession(_ http.ResponseWriter, _ *http.Request, _ *saml.IdpLogoutRequest) error {
	ti.loggedOut = true
	return nil
}

func newTestIDP(t *testing.T) *testIDP {
	key, cert := newKeyPair(t, "idp")
	ti := &testIDP{key: key, cert: cert}
	ti.idp = &saml.IdentityProvider{
		Key:         key,
		Certificate: cert,
		MetadataURL: mustURL("https://idp.example.com/metadata"),
		SSOURL:      mustURL("https://idp.example.com/sso"),
		LogoutURL:   mustURL("https://idp.example.com/slo"),
		LogoutBindings: []string{
			saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding,
		},
		AdvertiseSimpleSignSSO:  true,
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	return ti
}

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

// newTestConfig returns an SP Config that trusts ti, and registers the SP
// with ti.
func newTestConfig(t *testing.T, ti *testIDP) *samlsp.Config {
	t.Helper()
	key, cert := newKeyPair(t, "sp")
	cfg := &samlsp.Config{
		IdentityProviderMetadata: func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil },
		EntityID:                 "https://sp.example.com/saml/metadata",
		MetadataURL:              "https://sp.example.com/saml/metadata",
		ACSURL:                   "https://sp.example.com/saml/acs",
		SLOURL:                   "https://sp.example.com/saml/slo",
		Key:                      key,
		Certificate:              cert,
	}
	md, err := cfg.Metadata(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	ti.spMeta = md
	return cfg
}

var formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)

// formValues returns the hidden inputs of an auto-submitting POST form.
func formValues(body string) url.Values {
	v := url.Values{}
	for _, m := range formInput.FindAllStringSubmatch(body, -1) {
		v.Set(m[1], html.UnescapeString(m[2]))
	}
	return v
}

func postForm(target string, v url.Values) *http.Request {
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(v.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

// login sends msg to the IdP and returns the request the browser then posts
// to the ACS.
func login(t *testing.T, ti *testIDP, msg *samlsp.Message) *http.Request {
	t.Helper()
	var r *http.Request
	if u := msg.RedirectURL(); u != nil {
		r = httptest.NewRequest(http.MethodGet, u.String(), nil)
	} else {
		w := httptest.NewRecorder()
		msg.Write(w)
		r = postForm(msg.Destination, formValues(w.Body.String()))
	}
	w := httptest.NewRecorder()
	ti.idp.ServeSSO(w, r)
	if w.Code != http.StatusOK {
		t.Fatalf("IdP SSO: %d %s", w.Code, w.Body.String())
	}
	v := formValues(w.Body.String())
	if v.Get("SAMLResponse") == "" {
		t.Fatalf("IdP did not answer with a response: %s", w.Body.String())
	}
	return postForm("https://sp.example.com/saml/acs", v)
}

func TestLogin(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		t.Run(binding, func(t *testing.T) {
			ti := newTestIDP(t)
			cfg := newTestConfig(t, ti)
			cfg.SignRequests = true

			msg, err := cfg.AuthnRequest(t.Context(), "state-1", samlsp.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			if msg.Binding != binding || msg.ID == "" || msg.RelayState != "state-1" {
				t.Fatalf("unexpected message %+v", msg)
			}

			acs := login(t, ti, msg)
			if got := acs.FormValue("RelayState"); got != "state-1" {
				t.Errorf("RelayState = %q", got)
			}
			a, err := cfg.ParseResponse(context.Background(), acs, samlsp.WithRequestID(msg.ID))
			if err != nil {
				t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
			}
			if a.Subject != "alice@example.com" || a.NameID.Format != string(saml.EmailAddressNameIDFormat) {
				t.Errorf("subject = %q (%q)", a.Subject, a.NameID.Format)
			}
			if a.Issuer != ti.idp.Metadata().EntityID {
				t.Errorf("Issuer = %q", a.Issuer)
			}
			if a.InResponseTo != msg.ID {
				t.Errorf("InResponseTo = %q, want %q", a.InResponseTo, msg.ID)
			}
			if len(a.SessionIndexes) != 1 || a.SessionIndexes[0] != "index-1" {
				t.Errorf("SessionIndexes = %v", a.SessionIndexes)
			}

			var user struct {
				UID    string   `saml:"uid"`
				Groups []string `saml:"eduPersonAffiliation"`
				Absent string   `saml:"nope"`
			}
			if err := a.DecodeAttributes(&user); err != nil {
				t.Fatal(err)
			}
			if user.UID != "alice" || len(user.Groups) != 2 || user.Absent != "" {
				t.Errorf("decoded attributes = %+v (from %+v)", user, a.Attributes)
			}
		})
	}
}

func TestParseResponseRefusesOtherRequestID(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)
	if _, err := cfg.ParseResponse(context.Background(), acs, samlsp.WithRequestID("id-other")); !errors.Is(err, saml.ErrRequestIDMismatch) {
		t.Fatalf("ParseResponse with the wrong ID = %v, want ErrRequestIDMismatch", err)
	}
	// A solicited response does not pass as an unsolicited one.
	if _, err := cfg.ParseResponse(context.Background(), acs, samlsp.AllowUnsolicited); !errors.Is(err, saml.ErrRequestIDMismatch) {
		t.Fatalf("ParseResponse with AllowUnsolicited = %v, want ErrRequestIDMismatch", err)
	}
}

func TestParseResponseNeedsRequestID(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	r := postForm("https://sp.example.com/saml/acs", url.Values{"SAMLResponse": {"x"}})
	if _, err := cfg.ParseResponse(context.Background(), r); !errors.Is(err, samlsp.ErrNoRequestID) {
		t.Fatalf("err = %v", err)
	}
}

func decodeRedirectRequest(t *testing.T, u *url.URL) *saml.AuthnRequest {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(u.Query().Get("SAMLRequest"))
	if err != nil {
		t.Fatal(err)
	}
	xmlBytes, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	var req saml.AuthnRequest
	if err := xml.Unmarshal(xmlBytes, &req); err != nil {
		t.Fatal(err)
	}
	return &req
}

func TestAuthnRequestOptions(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s",
		samlsp.ForceAuthn,
		samlsp.IsPassive,
		samlsp.WithAuthnContext("minimum", "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"),
		samlsp.WithResponseBinding(saml.HTTPArtifactBinding),
	)
	if err != nil {
		t.Fatal(err)
	}
	req := decodeRedirectRequest(t, msg.RedirectURL())
	if req.ID != msg.ID {
		t.Errorf("ID = %q, want %q", req.ID, msg.ID)
	}
	if req.ForceAuthn == nil || !*req.ForceAuthn {
		t.Error("ForceAuthn not set")
	}
	if req.IsPassive == nil || !*req.IsPassive {
		t.Error("IsPassive not set")
	}
	if req.RequestedAuthnContext == nil || req.RequestedAuthnContext.Comparison != "minimum" {
		t.Errorf("RequestedAuthnContext = %+v", req.RequestedAuthnContext)
	}
	if req.ProtocolBinding != saml.HTTPArtifactBinding {
		t.Errorf("ProtocolBinding = %q", req.ProtocolBinding)
	}

	// Options apply to one request only.
	msg, err = cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	req = decodeRedirectRequest(t, msg.RedirectURL())
	if req.ForceAuthn != nil || req.IsPassive != nil || req.RequestedAuthnContext != nil {
		t.Errorf("options leaked into the next request: %+v", req)
	}
}

func TestAuthnRequestBindingErrors(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithBinding(saml.HTTPArtifactBinding)); err == nil {
		t.Error("expected an error for an unsupported binding")
	}
	cfg.Key = nil
	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithBinding(saml.HTTPPostSimpleSignBinding)); err == nil {
		t.Error("expected an error for SimpleSign without a key")
	}
}

var scriptRE = regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
var cspHashRE = regexp.MustCompile(`'(sha256-[^']+)'`)

// TestScriptHashes checks that the Content-Security-Policy that Message.Write
// sends allows the script of the form it writes.
func TestScriptHashes(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)

	msgs := make([]*samlsp.Message, 0, 6)
	for _, b := range []string{saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		m, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
		m, err = cfg.LogoutRequest(t.Context(), saml.NameID{Value: "alice"}, "s", samlsp.WithBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
		m, err = cfg.LogoutResponse(t.Context(), &samlsp.LogoutRequest{ID: "id-1", RelayState: "s"}, samlsp.WithBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
	}
	for _, m := range msgs {
		w := httptest.NewRecorder()
		m.Write(w)
		script := scriptRE.FindStringSubmatch(w.Body.String())
		if script == nil {
			t.Fatalf("no script in %s", w.Body.String())
		}
		sum := sha256.Sum256([]byte(script[1]))
		want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
		got := cspHashRE.FindStringSubmatch(w.Header().Get("Content-Security-Policy"))
		if got == nil || got[1] != want {
			t.Errorf("%s: CSP %q does not allow script hash %s", m.Binding, w.Header().Get("Content-Security-Policy"), want)
		}
	}
}

func TestServeMetadata(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, cfg.MetadataURL, nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/samlmetadata+xml" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	sp := md.SPSSODescriptors[0]
	if md.EntityID != cfg.EntityID || sp.AssertionConsumerServices[0].Location != cfg.ACSURL {
		t.Errorf("unexpected metadata %s", w.Body.String())
	}
	if len(sp.SingleLogoutServices) == 0 || sp.SingleLogoutServices[0].Location != cfg.SLOURL {
		t.Errorf("SLO not advertised: %+v", sp.SingleLogoutServices)
	}
}

func TestConfigErrors(t *testing.T) {
	ti := newTestIDP(t)
	good := newTestConfig(t, ti)
	for name, mutate := range map[string]func(*samlsp.Config){
		"no IdP metadata": func(c *samlsp.Config) { c.IdentityProviderMetadata = nil },
		"IdP metadata error": func(c *samlsp.Config) {
			c.IdentityProviderMetadata = func(context.Context) (*saml.EntityDescriptor, error) { return nil, errors.New("down") }
		},
		"not an IdP": func(c *samlsp.Config) {
			c.IdentityProviderMetadata = samlsp.StaticMetadata(&saml.EntityDescriptor{EntityID: "sp"})
		},
		"no ACS":           func(c *samlsp.Config) { c.ACSURL = "" },
		"relative ACS":     func(c *samlsp.Config) { c.ACSURL = "/saml/acs" },
		"no entity ID":     func(c *samlsp.Config) { c.EntityID, c.MetadataURL = "", "" },
		"sign without key": func(c *samlsp.Config) { c.Key, c.SignRequests = nil, true },
	} {
		cfg := *good
		mutate(&cfg)
		if _, err := cfg.AuthnRequest(t.Context(), "s"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestSPInitiatedLogout(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			ti := newTestIDP(t)
			cfg := newTestConfig(t, ti)
			msg, err := cfg.AuthnRequest(t.Context(), "s")
			if err != nil {
				t.Fatal(err)
			}
			a, err := cfg.ParseResponse(context.Background(), login(t, ti, msg), samlsp.WithRequestID(msg.ID))
			if err != nil {
				t.Fatal(err)
			}

			logout, err := cfg.LogoutRequest(t.Context(), a.NameID, "bye", samlsp.WithBinding(binding),
				samlsp.WithSessionIndex(a.SessionIndexes...))
			if err != nil {
				t.Fatal(err)
			}
			var r *http.Request
			if u := logout.RedirectURL(); u != nil {
				r = httptest.NewRequest(http.MethodGet, u.String(), nil)
			} else {
				w := httptest.NewRecorder()
				logout.Write(w)
				r = postForm(logout.Destination, formValues(w.Body.String()))
			}
			w := httptest.NewRecorder()
			ti.idp.ServeSLO(w, r)
			if !ti.loggedOut {
				t.Fatalf("IdP did not end the session: %d %s", w.Code, w.Body.String())
			}

			var back *http.Request
			if loc := w.Header().Get("Location"); loc != "" {
				back = httptest.NewRequest(http.MethodGet, loc, nil)
			} else {
				back = postForm(cfg.SLOURL, formValues(w.Body.String()))
			}
			resp, err := cfg.ParseLogoutResponse(t.Context(), back, logout.ID)
			if err != nil {
				t.Fatalf("ParseLogoutResponse: %v (%v)", err, errors.Unwrap(err))
			}
			if resp.InResponseTo != logout.ID {
				t.Errorf("InResponseTo = %q", resp.InResponseTo)
			}
			if _, err := cfg.ParseLogoutResponse(t.Context(), back); !errors.Is(err, samlsp.ErrNoRequestID) {
				t.Errorf("ParseLogoutResponse without IDs = %v", err)
			}
		})
	}
}

func TestIDPInitiatedLogout(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)

	// Build the LogoutRequest the IdP would send, signed with its key.
	req := &saml.LogoutRequest{
		ID:           "id-logout-1",
		Version:      "2.0",
		IssueInstant: time.Now().UTC(),
		Destination:  cfg.SLOURL,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: ti.idp.Metadata().EntityID},
		NameID:       &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"},
		SessionIndex: &saml.SessionIndex{Value: "index-1"},
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignEnveloped(req.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	r := postForm(cfg.SLOURL, url.Values{
		"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)},
		"RelayState":  {"idp-state"},
	})

	got, err := cfg.ParseLogoutRequest(t.Context(), r)
	if err != nil {
		t.Fatalf("ParseLogoutRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if got.ID != req.ID || got.NameID.Value != "alice@example.com" || got.RelayState != "idp-state" ||
		len(got.SessionIndexes) != 1 || got.SessionIndexes[0] != "index-1" {
		t.Fatalf("unexpected request %+v", got)
	}

	resp, err := cfg.LogoutResponse(t.Context(), got)
	if err != nil {
		t.Fatal(err)
	}
	u := resp.RedirectURL()
	if u == nil || u.Query().Get("SAMLResponse") == "" || u.Query().Get("RelayState") != "idp-state" ||
		u.Query().Get("Signature") == "" {
		t.Fatalf("unexpected response URL %v", u)
	}
	if !strings.HasPrefix(u.String(), "https://idp.example.com/slo?") {
		t.Errorf("response sent to %v", u)
	}

	// An unsigned request is refused.
	unsigned, _ := xml.Marshal(req)
	r = postForm(cfg.SLOURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(unsigned)}})
	if _, err := cfg.ParseLogoutRequest(t.Context(), r); err == nil {
		t.Error("expected an unsigned LogoutRequest to be refused")
	}
}

func TestLogoutUnsupported(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.LogoutURL = url.URL{}
	cfg := newTestConfig(t, ti)
	if _, err := cfg.LogoutRequest(t.Context(), saml.NameID{Value: "alice"}, ""); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Fatalf("err = %v, want ErrNoEndpoint", err)
	}
}

func TestParseMetadata(t *testing.T) {
	ti := newTestIDP(t)
	buf, err := xml.Marshal(ti.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	f, err := samlsp.ParseMetadata(buf)
	if err != nil {
		t.Fatal(err)
	}
	md, err := f(t.Context())
	if err != nil || md.EntityID != "https://idp.example.com/metadata" {
		t.Fatalf("got %v, %v", md, err)
	}
	if _, err := samlsp.ParseMetadata([]byte("<nope/>")); err == nil {
		t.Error("expected an error for bad metadata")
	}
}

func TestSPMetadataDoesNotNeedIdP(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	cfg.IdentityProviderMetadata = func(context.Context) (*saml.EntityDescriptor, error) {
		return nil, errors.New("IdP is down")
	}
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, cfg.MetadataURL, nil))
	if w.Code != http.StatusOK {
		t.Fatalf("ServeMetadata = %d", w.Code)
	}
}

// metadataServer serves ti's metadata, failing while fail is set, and counts
// requests.
type metadataServer struct {
	*httptest.Server
	hits atomic.Int32
	fail atomic.Bool
}

func newMetadataServer(t *testing.T, md *saml.EntityDescriptor) *metadataServer {
	buf, err := xml.Marshal(md)
	if err != nil {
		t.Fatal(err)
	}
	s := &metadataServer{}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		s.hits.Add(1)
		if s.fail.Load() {
			http.Error(w, "down", http.StatusServiceUnavailable)
			return
		}
		_, _ = w.Write(buf)
	}))
	t.Cleanup(s.Close)
	return s
}

func TestRemoteMetadata(t *testing.T) {
	ti := newTestIDP(t)
	srv := newMetadataServer(t, ti.idp.Metadata())

	// Cached between calls.
	f := samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client()))
	for range 3 {
		md, err := f(t.Context())
		if err != nil {
			t.Fatal(err)
		}
		if md.EntityID != "https://idp.example.com/metadata" {
			t.Fatalf("EntityID = %q", md.EntityID)
		}
	}
	if got := srv.hits.Load(); got != 1 {
		t.Errorf("fetched %d times, want 1", got)
	}

	// Refreshed after the refresh interval, and kept when a refresh fails.
	f = samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client()), samlsp.WithRefreshInterval(time.Nanosecond))
	if _, err := f(t.Context()); err != nil {
		t.Fatal(err)
	}
	srv.fail.Store(true)
	before := srv.hits.Load()
	time.Sleep(time.Millisecond)
	if _, err := f(t.Context()); err != nil {
		t.Fatalf("stale metadata not served: %v", err)
	}
	if srv.hits.Load() != before+1 {
		t.Error("metadata was not refreshed")
	}

	// Nothing to fall back on.
	f = samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client()))
	if _, err := f(t.Context()); err == nil {
		t.Error("expected an error")
	}
}

func TestRemoteMetadataWithConfig(t *testing.T) {
	ti := newTestIDP(t)
	srv := newMetadataServer(t, ti.idp.Metadata())
	cfg := newTestConfig(t, ti)
	cfg.IdentityProviderMetadata = samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client()))
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}
