package slo_test

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
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/slo"
)

const (
	spEntityID = "https://sp.example.com/saml/metadata"
	spSLOURL   = "https://sp.example.com/saml/slo"
)

func newKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
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

func mustURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
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

func (ti *testIDP) GetSession(http.ResponseWriter, *http.Request, *saml.IdpAuthnRequest) *saml.Session {
	return nil
}

func (ti *testIDP) InvalidateSession(http.ResponseWriter, *http.Request, *saml.IdpLogoutRequest) error {
	ti.loggedOut = true
	return nil
}

func newTestIDP(t *testing.T) *testIDP {
	t.Helper()
	key, cert := newKeyPair(t)
	ti := &testIDP{key: key, cert: cert}
	ti.idp = &saml.IdentityProvider{
		Key: key, Certificate: cert,
		MetadataURL: mustURL("https://idp.example.com/metadata"),
		SSOURL:      mustURL("https://idp.example.com/sso"),
		LogoutURL:   mustURL("https://idp.example.com/slo"),
		LogoutBindings: []string{
			saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding,
		},
		ServiceProviderProvider: ti,
		SessionProvider:         ti,
	}
	return ti
}

// newService returns a Config that trusts ti, with an SLO endpoint, and its
// Service, and registers the SP with ti.
func newService(t *testing.T, ti *testIDP, endpointOpts []slo.EndpointOption, opts ...samlsp.Option) (*samlsp.Config, *slo.Service) {
	t.Helper()
	key, cert := newKeyPair(t)
	idp := func(context.Context) (*saml.EntityDescriptor, error) { return ti.idp.Metadata(), nil }
	opts = append([]samlsp.Option{samlsp.WithSigningKey(key, cert), slo.Endpoint(spSLOURL, endpointOpts...)}, opts...)
	cfg, err := samlsp.New(spEntityID, idp, opts...)
	if err != nil {
		t.Fatal(err)
	}
	ti.spMeta = cfg.Metadata(t.Context())
	s, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	return cfg, s
}

var formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)

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

// browser returns the request the browser makes for msg.
func browser(t *testing.T, msg *samlsp.Message) *http.Request {
	t.Helper()
	if u := msg.RedirectURL(); u != nil {
		return httptest.NewRequest(http.MethodGet, u.String(), nil)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	return postForm(msg.Destination, formValues(w.Body.String()))
}

func inflateParam(t *testing.T, u *url.URL, param string) []byte {
	t.Helper()
	data, err := base64.StdEncoding.DecodeString(u.Query().Get(param))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := io.ReadAll(flate.NewReader(bytes.NewReader(data)))
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func TestSPInitiatedLogout(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		t.Run(binding, func(t *testing.T) {
			ti := newTestIDP(t)
			_, s := newService(t, ti, nil)
			alice := saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}

			msg, err := s.Request(t.Context(), alice, "bye", samlsp.WithBinding(binding), slo.WithSessionIndex("index-1"))
			if err != nil {
				t.Fatal(err)
			}
			w := httptest.NewRecorder()
			ti.idp.ServeSLO(w, browser(t, msg))
			if !ti.loggedOut {
				t.Fatalf("the IdP did not end the session: %d %s", w.Code, w.Body.String())
			}

			var back *http.Request
			if loc := w.Header().Get("Location"); loc != "" {
				back = httptest.NewRequest(http.MethodGet, loc, nil)
			} else {
				back = postForm(spSLOURL, formValues(w.Body.String()))
			}
			if !slo.IsResponse(back) || slo.IsRequest(back) {
				t.Error("the IdP's LogoutResponse is not recognized")
			}
			resp, err := s.ParseResponse(t.Context(), back, msg.ID)
			if err != nil {
				t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
			}
			if resp.InResponseTo != msg.ID {
				t.Errorf("InResponseTo = %q", resp.InResponseTo)
			}
			if _, err := s.ParseResponse(t.Context(), back); !errors.Is(err, slo.ErrNoRequestID) {
				t.Errorf("without IDs: %v", err)
			}
			if _, err := s.ParseResponse(t.Context(), back, msg.ID); !errors.Is(err, saml.ErrAssertionReplayed) {
				t.Errorf("replayed: %v", err)
			}
		})
	}
}

// idpLogoutRequest returns a LogoutRequest from ti for alice, signed with
// ti's key.
func idpLogoutRequest(t *testing.T, ti *testIDP) (*saml.LogoutRequest, []byte) {
	t.Helper()
	req := &saml.LogoutRequest{
		ID: "id-logout-1", Version: "2.0", IssueInstant: time.Now().UTC(), Destination: spSLOURL,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: ti.idp.Metadata().EntityID},
		NameID:       &saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"},
		SessionIndex: &saml.SessionIndex{Value: "index-1"},
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
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
	return req, buf
}

func TestIDPInitiatedLogout(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	req, buf := idpLogoutRequest(t, ti)
	r := postForm(spSLOURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}, "RelayState": {"idp-state"}})

	got, err := s.ParseRequest(t.Context(), r)
	if err != nil {
		t.Fatalf("ParseRequest: %v (%v)", err, errors.Unwrap(err))
	}
	if got.ID != req.ID || got.Issuer != ti.idp.Metadata().EntityID || got.NameID.Value != "alice@example.com" || got.RelayState != "idp-state" ||
		got.Binding != saml.HTTPPostBinding || len(got.SessionIndexes) != 1 {
		t.Fatalf("unexpected request %+v", got)
	}

	// The same request with the HTTP-POST-SimpleSign binding.
	idpSigner := &saml.ServiceProvider{Key: ti.key, Certificate: ti.cert}
	simpleReq := *req
	simpleReq.ID = "id-logout-simplesign"
	fields, err := idpSigner.SimpleSignValues("SAMLRequest", simpleReq.Element(), "idp-state", dsig.RSASHA256SignatureMethod)
	if err != nil {
		t.Fatal(err)
	}
	simple, err := s.ParseRequest(t.Context(), postForm(spSLOURL, fields))
	if err != nil {
		t.Fatalf("ParseRequest, SimpleSign: %v (%v)", err, errors.Unwrap(err))
	}
	if simple.Binding != saml.HTTPPostSimpleSignBinding || simple.RelayState != "idp-state" {
		t.Errorf("SimpleSign request: %+v", simple)
	}

	msg, err := s.Response(t.Context(), got)
	if err != nil {
		t.Fatal(err)
	}
	u := msg.RedirectURL()
	if u == nil || u.Query().Get("RelayState") != "idp-state" || u.Query().Get("Signature") == "" {
		t.Fatalf("response URL %v", u)
	}
	var resp saml.LogoutResponse
	if err := xml.Unmarshal(inflateParam(t, u, "SAMLResponse"), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.ID != msg.ID || resp.InResponseTo != req.ID || resp.Status.StatusCode.Value != saml.StatusSuccess {
		t.Errorf("response %+v", resp)
	}

	// WithStatus.
	msg, err = s.Response(t.Context(), got, slo.WithStatus(saml.Status{StatusCode: saml.StatusCode{
		Value: saml.StatusSuccess, StatusCode: &saml.StatusCode{Value: saml.StatusPartialLogout},
	}}))
	if err != nil {
		t.Fatal(err)
	}
	resp = saml.LogoutResponse{}
	if err := xml.Unmarshal(inflateParam(t, msg.RedirectURL(), "SAMLResponse"), &resp); err != nil {
		t.Fatal(err)
	}
	if resp.Status.StatusCode.StatusCode == nil || resp.Status.StatusCode.StatusCode.Value != saml.StatusPartialLogout {
		t.Errorf("status %+v", resp.Status)
	}

	// Unsigned is refused.
	unsigned, _ := xml.Marshal(req)
	r = postForm(spSLOURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(unsigned)}})
	if _, err := s.ParseRequest(t.Context(), r); err == nil {
		t.Error("an unsigned LogoutRequest was accepted")
	}
	w := httptest.NewRecorder()
	slo.WriteRequestError(w, r)
	if w.Code != http.StatusBadRequest {
		t.Errorf("WriteRequestError: %d", w.Code)
	}
}

var (
	scriptRE  = regexp.MustCompile(`(?s)<script[^>]*>(.*?)</script>`)
	cspHashRE = regexp.MustCompile(`'(sha256-[^']+)'`)
)

// TestFormMessages checks the IDs and Content-Security-Policy of logout
// messages sent with the POST bindings.
func TestFormMessages(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	req := &slo.Request{ID: "id-req", RelayState: "r"}
	for _, binding := range []string{saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		msgs := make([]*samlsp.Message, 0, 2)
		m, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, "r", samlsp.WithBinding(binding))
		if err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
		if m, err = s.Response(t.Context(), req, samlsp.WithBinding(binding)); err != nil {
			t.Fatal(err)
		}
		msgs = append(msgs, m)
		for _, m := range msgs {
			w := httptest.NewRecorder()
			m.Write(w)
			script := scriptRE.FindStringSubmatch(w.Body.String())
			sum := sha256.Sum256([]byte(script[1]))
			want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
			if got := cspHashRE.FindStringSubmatch(w.Header().Get("Content-Security-Policy")); got == nil || got[1] != want {
				t.Errorf("%s: CSP does not allow the script", binding)
			}
			fields := formValues(w.Body.String())
			param := "SAMLRequest"
			if fields.Get(param) == "" {
				param = "SAMLResponse"
			}
			buf, _ := base64.StdEncoding.DecodeString(fields.Get(param))
			if m.ID == "" || !strings.Contains(string(buf), `ID="`+m.ID+`"`) {
				t.Errorf("%s: Message.ID %q not in %s", binding, m.ID, buf)
			}
		}
	}
}

func TestReasonAndNotOnOrAfter(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	deadline := time.Now().Add(2 * time.Minute).Truncate(time.Millisecond)
	msg, err := s.Request(t.Context(), saml.NameID{Value: "alice@example.com"}, "s",
		slo.WithReason(saml.LogoutReasonAdmin), slo.WithNotOnOrAfter(deadline))
	if err != nil {
		t.Fatal(err)
	}
	var req saml.LogoutRequest
	if err := xml.Unmarshal(inflateParam(t, msg.RedirectURL(), "SAMLRequest"), &req); err != nil {
		t.Fatal(err)
	}
	if req.Reason != saml.LogoutReasonAdmin || req.NotOnOrAfter == nil || !req.NotOnOrAfter.Equal(deadline) {
		t.Errorf("Reason %q, NotOnOrAfter %v", req.Reason, req.NotOnOrAfter)
	}
	w := httptest.NewRecorder()
	ti.idp.ServeSLO(w, browser(t, msg))
	if !ti.loggedOut {
		t.Errorf("the IdP refused: %d %s", w.Code, w.Body.String())
	}
}

func TestEncryptNameID(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, []slo.EndpointOption{slo.EncryptNameID})
	msg, err := s.Request(t.Context(), saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	sent := string(inflateParam(t, msg.RedirectURL(), "SAMLRequest"))
	if !strings.Contains(sent, "EncryptedID") || strings.Contains(sent, "alice@example.com") {
		t.Fatalf("the NameID is not encrypted: %s", sent)
	}
	w := httptest.NewRecorder()
	ti.idp.ServeSLO(w, browser(t, msg))
	if !ti.loggedOut {
		t.Errorf("the IdP refused: %d %s", w.Code, w.Body.String())
	}
}

func TestNoEndpoint(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.LogoutURL = url.URL{}
	_, s := newService(t, ti, nil)
	if _, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, ""); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Fatalf("err = %v, want ErrNoEndpoint", err)
	}
}

func TestConfiguration(t *testing.T) {
	ti := newTestIDP(t)
	idp := samlsp.StaticMetadata(ti.idp.Metadata())
	key, cert := newKeyPair(t)

	cfg, s := newService(t, ti, []slo.EndpointOption{slo.BackChannel})
	if s.URL() != spSLOURL {
		t.Errorf("URL = %q", s.URL())
	}
	if s.Path() != "/saml/slo" {
		t.Errorf("Path = %q", s.Path())
	}
	endpoints := cfg.Metadata(t.Context()).SPSSODescriptors[0].SingleLogoutServices
	bindings := make([]string, 0, len(endpoints))
	for _, e := range endpoints {
		if e.Location != spSLOURL {
			t.Errorf("endpoint at %s", e.Location)
		}
		bindings = append(bindings, e.Binding)
	}
	if strings.Join(bindings, " ") != saml.HTTPRedirectBinding+" "+saml.HTTPPostBinding+" "+saml.SOAPBinding {
		t.Errorf("bindings %v", bindings)
	}

	for name, opts := range map[string][]samlsp.Option{
		"relative URL":         {samlsp.WithSigningKey(key, cert), slo.Endpoint("/slo")},
		"back channel, no key": {slo.Endpoint(spSLOURL, slo.BackChannel)},
		"no key":               {slo.Endpoint(spSLOURL)},
	} {
		if _, err := samlsp.New(spEntityID, idp, opts...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	plain, err := samlsp.New(spEntityID, idp, samlsp.WithSigningKey(key, cert))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := slo.New(plain); err == nil {
		t.Error("slo.New accepted a Config without an SLO endpoint")
	}
}

// TestResponseLocation checks that LogoutResponses go to the
// ResponseLocation of the IdP's SingleLogoutService (saml-metadata
// §2.2.2), and LogoutRequests to its Location.
func TestResponseLocation(t *testing.T) {
	const responseURL = "https://idp.example.com/slo/response"
	ti := newTestIDP(t)
	md := ti.idp.Metadata()
	for i := range md.IDPSSODescriptors[0].SingleLogoutServices {
		md.IDPSSODescriptors[0].SingleLogoutServices[i].ResponseLocation = responseURL
	}
	key, cert := newKeyPair(t)
	cfg, err := samlsp.New(spEntityID, samlsp.StaticMetadata(md), samlsp.WithSigningKey(key, cert), slo.Endpoint(spSLOURL))
	if err != nil {
		t.Fatal(err)
	}
	s, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding, saml.HTTPPostSimpleSignBinding} {
		resp, err := s.Response(t.Context(), &slo.Request{ID: "id-req", RelayState: "r"}, samlsp.WithBinding(binding))
		if err != nil {
			t.Fatal(err)
		}
		r := browser(t, resp)
		if got := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path; got != responseURL {
			t.Errorf("%s: response sent to %s", binding, got)
		}
		if err := r.ParseForm(); err != nil {
			t.Fatal(err)
		}
		var buf []byte
		if binding == saml.HTTPRedirectBinding {
			buf = inflateParam(t, r.URL, "SAMLResponse")
		} else if buf, err = base64.StdEncoding.DecodeString(r.PostForm.Get("SAMLResponse")); err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(buf), `Destination="`+responseURL+`"`) {
			t.Errorf("%s: Destination is not the ResponseLocation: %s", binding, buf)
		}

		req, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, "r", samlsp.WithBinding(binding))
		if err != nil {
			t.Fatal(err)
		}
		r = browser(t, req)
		if got := r.URL.Scheme + "://" + r.URL.Host + r.URL.Path; got != "https://idp.example.com/slo" {
			t.Errorf("%s: request sent to %s", binding, got)
		}
	}
}

// TestUnsignedRefused checks that logout messages are not sent through the
// browser unsigned when a ServiceProviderOption of the call leaves no key
// to sign them with (saml-profiles §4.4.4.1).
func TestUnsignedRefused(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	noKey := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.LogoutSignatureMethod = "" })
	if _, err := s.Request(t.Context(), saml.NameID{Value: "alice"}, "r", noKey); err == nil {
		t.Error("Request sent an unsigned LogoutRequest")
	}
	if _, err := s.Response(t.Context(), &slo.Request{ID: "id-req"}, noKey); err == nil {
		t.Error("Response sent an unsigned LogoutResponse")
	}
}
