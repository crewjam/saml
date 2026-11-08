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
	noSession bool          // answer an IsPassive request with NoPassive
	authnAge  time.Duration // how long ago the session authenticated the user
}

func (ti *testIDP) GetServiceProvider(_ *http.Request, id string) (*saml.EntityDescriptor, error) {
	if ti.spMeta != nil && id == ti.spMeta.EntityID {
		return ti.spMeta, nil
	}
	return nil, errors.New("unknown service provider")
}

func (ti *testIDP) GetSession(w http.ResponseWriter, _ *http.Request, req *saml.IdpAuthnRequest) *saml.Session {
	if ti.noSession && req.Request.IsPassive != nil && *req.Request.IsPassive {
		if err := ti.idp.SendErrorResponse(w, req, &saml.StatusError{TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive}); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return nil
	}
	return &saml.Session{
		ID:           "session-1",
		Index:        "index-1",
		CreateTime:   time.Now().Add(-ti.authnAge),
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

const (
	spEntityID = "https://sp.example.com/saml/metadata"
	spACSURL   = "https://sp.example.com/saml/acs"
)

// staticIDP returns a MetadataFunc for ti's metadata.
func staticIDP(ti *testIDP) samlsp.MetadataFunc {
	return func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil }
}

// newTestConfig returns an SP Config that trusts ti, and registers the SP
// with ti.
func newTestConfig(t *testing.T, ti *testIDP, opts ...samlsp.Option) *samlsp.Config {
	t.Helper()
	return newTestConfigWithIDP(t, ti, staticIDP(ti), opts...)
}

// newTestConfigWithIDP is newTestConfig with the IdP metadata from idp.
func newTestConfigWithIDP(t *testing.T, ti *testIDP, idp samlsp.MetadataFunc, opts ...samlsp.Option) *samlsp.Config {
	t.Helper()
	key, cert := newKeyPair(t, "sp")
	opts = append([]samlsp.Option{samlsp.WithSigningKey(key, cert)}, opts...)
	cfg, err := samlsp.New(spEntityID, idp, opts...)
	if err != nil {
		t.Fatal(err)
	}
	ti.spMeta = cfg.Metadata(t.Context())
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
			cfg := newTestConfig(t, ti, samlsp.SignAuthnRequests)

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
				UID            string   `saml:"urn:oid:0.9.2342.19200300.100.1.1"`
				Groups         []string `saml:"urn:oid:1.3.6.1.4.1.5923.1.1.1.1"`
				ByFriendlyName string   `saml:"uid"` // FriendlyName does not identify an attribute
				Absent         string   `saml:"nope"`
			}
			if err := a.DecodeAttributes(&user); err != nil {
				t.Fatal(err)
			}
			for _, at := range a.Attributes {
				if len(at.Types) != len(at.Values) || at.Types[0] != "xs:string" {
					t.Errorf("attribute %s: Types %q for Values %q", at.Name, at.Types, at.Values)
				}
			}
			if user.UID != "alice" || len(user.Groups) != 2 || user.ByFriendlyName != "" || user.Absent != "" {
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

// An IdP that cannot authenticate the user passively answers with
// Responder and NoPassive, which ParseResponse reports in saml.ErrBadStatus.
func TestIsPassiveNoPassive(t *testing.T) {
	ti := newTestIDP(t)
	ti.noSession = true
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.IsPassive)
	if err != nil {
		t.Fatal(err)
	}
	_, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID))
	if !errors.Is(err, saml.ErrBadStatus{Status: saml.StatusResponder, SubStatus: saml.StatusNoPassive}) {
		t.Fatalf("err = %v (%v), want NoPassive", err, errors.Unwrap(err))
	}
}

// InResponseTo is the request ID the assertion was accepted for, and
// empty for a response accepted as unsolicited, even one that names a
// request a ValidateRequestID hook let through.
func TestAssertionInResponseTo(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)
	acceptAny := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.ValidateRequestID = func(saml.Response, []string) error { return nil }
	})
	a, err := cfg.ParseResponse(t.Context(), acs, samlsp.AllowUnsolicited, acceptAny)
	if err != nil {
		t.Fatal(err)
	}
	if a.InResponseTo != "" {
		t.Errorf("unsolicited: InResponseTo = %q, want \"\"", a.InResponseTo)
	}

	msg, err = cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	a, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID("id-other"), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	if a.InResponseTo != msg.ID {
		t.Errorf("solicited: InResponseTo = %q, want %q", a.InResponseTo, msg.ID)
	}
}

// WithMaxAuthnAge refuses an assertion whose AuthnInstant is older than
// it allows, beyond saml.MaxClockSkew.
func TestWithMaxAuthnAge(t *testing.T) {
	for _, tc := range []struct {
		authnAge, maxAge time.Duration
		wantErr          bool
	}{
		{0, 10 * time.Minute, false},
		{10*time.Minute + saml.MaxClockSkew - time.Minute, 10 * time.Minute, false},
		{time.Hour, 10 * time.Minute, true},
		{time.Hour, 2 * time.Hour, false},
	} {
		ti := newTestIDP(t)
		ti.authnAge = tc.authnAge
		cfg := newTestConfig(t, ti)
		msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.ForceAuthn)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), samlsp.WithMaxAuthnAge(tc.maxAge))
		var invalid *saml.InvalidResponseError
		if tc.wantErr && (!errors.Is(err, samlsp.ErrAuthnTooOld) || !errors.As(err, &invalid)) || !tc.wantErr && err != nil {
			t.Errorf("authenticated %s ago, max %s: err = %v (%v)", tc.authnAge, tc.maxAge, err, errors.Unwrap(err))
		}
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
		samlsp.WithAuthnContext(saml.AuthnContextComparisonMinimum, saml.AuthnContextPasswordProtectedTransport, saml.AuthnContextX509),
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
	if rac := req.RequestedAuthnContext; rac == nil || rac.Comparison != "minimum" ||
		len(rac.AuthnContextClassRefs) != 2 || rac.AuthnContextClassRefs[1] != string(saml.AuthnContextX509) {
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
	noKey, err := samlsp.New(spEntityID, staticIDP(ti))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := noKey.AuthnRequest(t.Context(), "s", samlsp.WithBinding(saml.HTTPPostSimpleSignBinding)); err == nil {
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

	msgs := make([]*samlsp.Message, 0, 2)
	for _, b := range []string{saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		m, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithBinding(b), samlsp.WithScriptNonce("n"))
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
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "application/samlmetadata+xml" {
		t.Fatalf("%d %q", w.Code, w.Header().Get("Content-Type"))
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	sp := md.SPSSODescriptors[0]
	if md.EntityID != spEntityID || sp.AssertionConsumerServices[0].Location != spACSURL {
		t.Errorf("unexpected metadata %s", w.Body.String())
	}
	if len(sp.SingleLogoutServices) != 0 {
		t.Errorf("SLO advertised without x/samlsp/slo: %+v", sp.SingleLogoutServices)
	}
}

func TestNewErrors(t *testing.T) {
	ti := newTestIDP(t)
	idp := staticIDP(ti)
	for name, f := range map[string]func() (*samlsp.Config, error){
		"no entity ID":     func() (*samlsp.Config, error) { return samlsp.New("", idp) },
		"URN, default ACS": func() (*samlsp.Config, error) { return samlsp.New("urn:example:sp", idp) },
		"relative ACS": func() (*samlsp.Config, error) {
			return samlsp.New(spEntityID, idp, samlsp.WithACSURL("/saml/acs"))
		},
		"ACS without host": func() (*samlsp.Config, error) { return samlsp.New(spEntityID, idp, samlsp.WithACSURL("file:///acs")) },
		"sign without key": func() (*samlsp.Config, error) { return samlsp.New(spEntityID, idp, samlsp.SignAuthnRequests) },
	} {
		if _, err := f(); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestNewURLs(t *testing.T) {
	idp := staticIDP(newTestIDP(t))
	for _, tt := range []struct {
		entityID string
		opts     []samlsp.Option
		acs      string
	}{
		{"https://sp.example.com/saml/metadata", nil, "https://sp.example.com/saml/acs"},
		{"https://sp.example.com/saml/", nil, "https://sp.example.com/saml/acs"},
		{"https://sp.example.com", nil, "https://sp.example.com/acs"},
		{"https://sp.example.com/saml/metadata", []samlsp.Option{samlsp.WithACSURL("https://sp.example.com/sso/consume")}, "https://sp.example.com/sso/consume"},
		{"urn:example:sp", []samlsp.Option{samlsp.WithACSURL("https://sp.example.com/acs")}, "https://sp.example.com/acs"},
	} {
		cfg, err := samlsp.New(tt.entityID, idp, tt.opts...)
		if err != nil {
			t.Errorf("%s: %v", tt.entityID, err)
			continue
		}
		if cfg.ACSURL() != tt.acs {
			t.Errorf("%s: ACS %q, want %q", tt.entityID, cfg.ACSURL(), tt.acs)
		}
		if got := cfg.Metadata(t.Context()).SPSSODescriptors[0].AssertionConsumerServices[0].Location; got != tt.acs {
			t.Errorf("%s: metadata ACS %q", tt.entityID, got)
		}
	}
}

func TestIdentityProviderErrors(t *testing.T) {
	ti := newTestIDP(t)
	for name, idp := range map[string]samlsp.MetadataFunc{
		"error":      func(context.Context) (*saml.EntityDescriptor, error) { return nil, errors.New("down") },
		"not an IdP": samlsp.StaticMetadata(&saml.EntityDescriptor{EntityID: "sp"}),
		"nil":        samlsp.StaticMetadata(nil),
	} {
		cfg := newTestConfigWithIDP(t, ti, idp)
		if _, err := cfg.AuthnRequest(t.Context(), "s"); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestStaticMetadataBytes(t *testing.T) {
	ti := newTestIDP(t)
	buf, err := xml.Marshal(ti.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	md, err := samlsp.StaticMetadataBytes(buf)(t.Context())
	if err != nil || md.EntityID != "https://idp.example.com/metadata" {
		t.Fatalf("got %v, %v", md, err)
	}

	// Invalid metadata fails every call, and so every Config method.
	for _, bad := range [][]byte{[]byte("<nope/>"), []byte(`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="sp"/>`)} {
		f := samlsp.StaticMetadataBytes(bad)
		for range 2 {
			if _, err := f(t.Context()); err == nil {
				t.Errorf("%s: expected an error", bad)
			}
		}
		cfg := newTestConfigWithIDP(t, ti, f)
		if _, err := cfg.AuthnRequest(t.Context(), "s"); err == nil {
			t.Errorf("%s: AuthnRequest succeeded", bad)
		}
	}
}

func TestSPMetadataDoesNotNeedIdP(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfigWithIDP(t, ti, func(context.Context) (*saml.EntityDescriptor, error) {
		return nil, errors.New("IdP is down")
	})
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
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

func TestRemoteMetadataWithConfig(t *testing.T) {
	ti := newTestIDP(t)
	srv := newMetadataServer(t, ti.idp.Metadata())
	cfg := newTestConfigWithIDP(t, ti, samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client())))
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}

func TestServiceProviderOptions(t *testing.T) {
	ti := newTestIDP(t)
	var order []string
	cfg := newTestConfig(t, ti, samlsp.WithServiceProvider(func(*saml.ServiceProvider) { order = append(order, "config") }))
	order = nil // registering the SP built its metadata
	perCall := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		order = append(order, "call")
		f := true
		sp.ForceAuthn = &f
	})
	msg, err := cfg.AuthnRequest(t.Context(), "s", perCall)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "config,call" {
		t.Errorf("options ran in order %v", order)
	}
	if req := decodeRedirectRequest(t, msg.RedirectURL()); req.ForceAuthn == nil || !*req.ForceAuthn {
		t.Error("per-call option was not applied")
	}

	// Per-call options apply to that call only.
	order = nil
	msg, err = cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(order, ",") != "config" {
		t.Errorf("options ran in order %v", order)
	}
	if req := decodeRedirectRequest(t, msg.RedirectURL()); req.ForceAuthn != nil {
		t.Error("per-call option leaked into the next call")
	}

	// A ServiceProviderOption is also a ResponseOption and a MessageOption.
	called := 0
	count := samlsp.WithServiceProvider(func(*saml.ServiceProvider) { called++ })
	msg, err = cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), count); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.Send(t.Context(), pingRequest(), count); err != nil {
		t.Fatal(err)
	}
	if called != 2 {
		t.Errorf("option called %d times, want 2", called)
	}
}

func TestSignMetadata(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.SignMetadata)
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	if w.Code != http.StatusOK || !strings.Contains(w.Body.String(), "SignatureValue") {
		t.Fatalf("metadata is not signed: %d %s", w.Code, w.Body.String())
	}
}

func TestHardeningDefaults(t *testing.T) {
	ti := newTestIDP(t)
	var got saml.ServiceProvider
	cfg := newTestConfig(t, ti)
	if _, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { got = *sp })); err != nil {
		t.Fatal(err)
	}
	for name, on := range map[string]bool{
		"ValidateAuthnContextClassRef": got.ValidateAuthnContextClassRef,
		"RejectUnknownConditions":      got.RejectUnknownConditions,
		"RequireSignedResponseForCBC":  got.RequireSignedResponseForCBC,
		"RejectSHA1Signatures":         got.RejectSHA1Signatures,
		"RejectExpiredIDPMetadata":     got.RejectExpiredIDPMetadata,
		"RequireStandardArtifacts":     got.RequireStandardArtifacts,
		"LimitRelayStateLength":        got.LimitRelayStateLength,
		"!AllowInsecureSOAPEndpoints":  !got.AllowInsecureSOAPEndpoints,
		"!IgnoreCertificateExpiry":     !got.IgnoreCertificateExpiry,
	} {
		if !on {
			t.Errorf("%s is not set", name)
		}
	}

	if _, err := cfg.AuthnRequest(t.Context(), strings.Repeat("x", 81)); err == nil {
		t.Error("a RelayState longer than 80 bytes was accepted")
	}
}

func TestAuthnContextChecked(t *testing.T) {
	ti := newTestIDP(t) // authenticates with PasswordProtectedTransport
	cfg := newTestConfig(t, ti)

	for _, tt := range []struct {
		name    string
		ctx     samlsp.AuthnContextOption
		wantErr error
	}{
		{"satisfied", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509, saml.AuthnContextPasswordProtectedTransport), nil},
		{"not satisfied", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509), saml.ErrAuthnContextMismatch},
		{"no comparator", samlsp.WithAuthnContext(saml.AuthnContextComparisonMinimum, saml.AuthnContextPassword), saml.ErrUnsupported},
	} {
		msg, err := cfg.AuthnRequest(t.Context(), "s", tt.ctx)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), tt.ctx)
		if tt.wantErr == nil && err != nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}

	// With a comparator, "minimum" is decided by it.
	cfg = newTestConfig(t, ti, samlsp.WithAuthnContextComparator(
		func(c saml.AuthnContextComparison, requested []saml.AuthnContextClass, got saml.AuthnContextClass) bool {
			return c == saml.AuthnContextComparisonMinimum && requested[0] == saml.AuthnContextPassword &&
				got == saml.AuthnContextPasswordProtectedTransport
		}))
	minimum := samlsp.WithAuthnContext(saml.AuthnContextComparisonMinimum, saml.AuthnContextPassword)
	msg, err := cfg.AuthnRequest(t.Context(), "s", minimum)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), minimum); err != nil {
		t.Errorf("minimum with comparator: %v", err)
	}
}

func TestReplayRefusedByDefault(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)
	if _, err := cfg.ParseResponse(t.Context(), acs, samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
	again := postForm(spACSURL, acs.PostForm)
	if _, err := cfg.ParseResponse(t.Context(), again, samlsp.WithRequestID(msg.ID)); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("replayed Response: err = %v, want ErrAssertionReplayed", err)
	}
}

type recordingReplayState struct {
	keys [][]byte
	ctxs []context.Context
}

func (s *recordingReplayState) Consume(ctx context.Context, key []byte, _ time.Time) error {
	s.keys = append(s.keys, key)
	s.ctxs = append(s.ctxs, ctx)
	return nil
}

type requestKey struct{}

func TestWithReplayState(t *testing.T) {
	ti := newTestIDP(t)
	state := &recordingReplayState{}
	cfg := newTestConfig(t, ti, samlsp.WithReplayState(state))
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.WithValue(t.Context(), requestKey{}, "request-1")
	a, err := cfg.ParseResponse(ctx, login(t, ti, msg), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	// The key is that of the IdP's entity ID and the assertion's ID.
	if want := samlsp.ReplayKey(ti.idp.Metadata().EntityID, a.ID); len(state.keys) != 1 || !bytes.Equal(state.keys[0], want) {
		t.Errorf("recorded %x, want [%x]", state.keys, want)
	}
	// The record is made with the context of the ParseResponse call.
	if len(state.ctxs) != 1 || state.ctxs[0].Value(requestKey{}) != "request-1" {
		t.Error("Consume did not get the context of ParseResponse")
	}
}

// decodedResponse returns the XML of the SAMLResponse posted in r.
func decodedResponse(t *testing.T, r *http.Request) string {
	t.Helper()
	if err := r.ParseForm(); err != nil {
		t.Fatal(err)
	}
	buf, err := base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	return string(buf)
}
