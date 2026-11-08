package samlidp_test

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

const (
	idpEntityID = "https://idp.example.com/saml/metadata"
	spEntityID  = "https://sp.example.com/saml/metadata"
)

var (
	keysOnce         sync.Once
	idpKey, spKey    *rsa.PrivateKey
	idpCert, spCert  *x509.Certificate
	ecKey            *ecdsa.PrivateKey
	ecCert           *x509.Certificate
	errKeysGenerated error
)

// keys returns the test keys, made once per test binary.
func keys(t *testing.T) {
	t.Helper()
	keysOnce.Do(func() {
		var err error
		if idpKey, idpCert, err = rsaKeyPair("idp"); err != nil {
			errKeysGenerated = err
			return
		}
		if spKey, spCert, err = rsaKeyPair("sp"); err != nil {
			errKeysGenerated = err
			return
		}
		ecKey, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			errKeysGenerated = err
			return
		}
		ecCert, errKeysGenerated = selfSigned("ec", ecKey)
	})
	if errKeysGenerated != nil {
		t.Fatal(errKeysGenerated)
	}
}

func rsaKeyPair(name string) (*rsa.PrivateKey, *x509.Certificate, error) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}
	cert, err := selfSigned(name, key)
	return key, cert, err
}

func selfSigned(name string, key crypto.Signer) (*x509.Certificate, error) {
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: name},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(24 * time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(der)
}

// pair is an IdP of this package and an SP of x/samlsp that trust each
// other.
type pair struct {
	idp *samlidp.Config
	sp  *samlsp.Config
}

func newPair(t *testing.T, idpOpts []samlidp.Option, spOpts []samlsp.Option) *pair {
	t.Helper()
	return newPairWithMetadata(t, idpOpts, spOpts, nil)
}

// newPairWithMetadata is newPair, with the SP metadata that the IdP sees
// changed by edit, if it is not nil.
func newPairWithMetadata(t *testing.T, idpOpts []samlidp.Option, spOpts []samlsp.Option, edit func(*saml.EntityDescriptor)) *pair {
	t.Helper()
	keys(t)
	p := &pair{}
	idpMetadata := func(context.Context) (*saml.EntityDescriptor, error) { return p.idp.Metadata(), nil }
	var err error
	p.sp, err = samlsp.New(spEntityID, idpMetadata, append([]samlsp.Option{samlsp.WithSigningKey(spKey, spCert)}, spOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	spMetadata := p.sp.Metadata(context.Background())
	if edit != nil {
		edit(spMetadata)
	}
	sps := samlidp.StaticServiceProviders(spMetadata)
	p.idp, err = samlidp.New(idpEntityID, sps, append([]samlidp.Option{samlidp.WithSigningKey(idpKey, idpCert)}, idpOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	return p
}

// request returns the http.Request with which the browser delivers msg,
// a message from the SP, to the IdP.
func browserRequest(t *testing.T, msg *samlsp.Message) *http.Request {
	t.Helper()
	if u := msg.RedirectURL(); u != nil {
		return httptest.NewRequest(http.MethodGet, u.String(), http.NoBody)
	}
	return postForm(t, msg.Destination, formOf(t, msg))
}

// formOf returns the fields of the form that h writes.
func formOf(t *testing.T, h http.Handler) url.Values {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/", http.NoBody))
	body := rec.Body.String()
	fields := url.Values{}
	for _, part := range strings.Split(body, "<input ")[1:] {
		if !strings.Contains(part, `type="hidden"`) {
			continue
		}
		name := between(part, `name="`, `"`)
		value := between(part, `value="`, `"`)
		value = strings.NewReplacer("&#43;", "+", "&#61;", "=", "&amp;", "&", "&#34;", `"`, "&#39;", "'", "&lt;", "<", "&gt;", ">").Replace(value)
		fields.Add(name, value)
	}
	if len(fields) == 0 {
		t.Fatalf("no form in %s", body)
	}
	return fields
}

func between(s, start, end string) string {
	_, rest, _ := strings.Cut(s, start)
	v, _, _ := strings.Cut(rest, end)
	return v
}

func postForm(t *testing.T, target string, fields url.Values) *http.Request {
	t.Helper()
	r := httptest.NewRequest(http.MethodPost, target, strings.NewReader(fields.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return r
}

var testSubject = samlidp.Subject{
	NameID:       "transient-1234",
	AuthnInstant: time.Now().Add(-time.Minute),
	SessionIndex: "session-1",
	Attributes: []samlidp.Attribute{
		{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri", Values: []string{"alice@example.com"}},
		{Name: "groups", Values: []string{"admins", "users"}},
	},
}

// login runs a login from the SP's AuthnRequest to its verified assertion.
func (p *pair) login(t *testing.T, authnOpts []samlsp.AuthnOption, subject samlidp.Subject) (*samlsp.Assertion, *samlidp.AuthnRequest) {
	t.Helper()
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "relay-state", authnOpts...)
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != msg.ID || req.ServiceProvider != spEntityID || req.RelayState != "relay-state" {
		t.Fatalf("got %+v", req)
	}
	resp, err := p.idp.Response(ctx, req, subject)
	if err != nil {
		t.Fatal(err)
	}
	if resp.InResponseTo != msg.ID || resp.Destination != p.sp.ACSURL() || resp.RelayState != "relay-state" {
		t.Fatalf("got %+v", resp)
	}
	a, err := p.sp.ParseResponse(ctx, postForm(t, resp.Destination, formOf(t, resp)), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	return a, req
}

func TestLogin(t *testing.T) {
	keys(t)
	for _, tc := range []struct {
		name  string
		authn []samlsp.AuthnOption
		sp    []samlsp.Option
		idp   []samlidp.Option
	}{
		{name: "redirect"},
		{name: "post", authn: []samlsp.AuthnOption{samlsp.WithBinding(saml.HTTPPostBinding)}},
		{name: "signed redirect", sp: []samlsp.Option{samlsp.SignAuthnRequests}},
		{name: "signed post", sp: []samlsp.Option{samlsp.SignAuthnRequests}, authn: []samlsp.AuthnOption{samlsp.WithBinding(saml.HTTPPostBinding)}},
		{name: "signed simplesign", sp: []samlsp.Option{samlsp.SignAuthnRequests}, authn: []samlsp.AuthnOption{samlsp.WithBinding(saml.HTTPPostSimpleSignBinding)},
			idp: []samlidp.Option{samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.AdvertiseSimpleSignSSO = true })}},
		{name: "required signature", sp: []samlsp.Option{samlsp.SignAuthnRequests}, idp: []samlidp.Option{samlidp.RequireSignedAuthnRequests}},
		{name: "encrypted", sp: []samlsp.Option{samlsp.WithEncryptionKey(spKey, spCert)}},
		{name: "ecdsa", idp: []samlidp.Option{samlidp.WithSigningKey(ecKey, ecCert)}},
		{name: "sha512", idp: []samlidp.Option{samlidp.WithSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#rsa-sha512")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			p := newPair(t, tc.idp, tc.sp)
			a, _ := p.login(t, tc.authn, testSubject)
			if a.Subject != "transient-1234" || a.NameID.Format != string(saml.TransientNameIDFormat) {
				t.Errorf("NameID = %+v", a.NameID)
			}
			if a.Issuer != idpEntityID {
				t.Errorf("Issuer = %q", a.Issuer)
			}
			if got := a.Attributes.Values("groups"); len(got) != 2 || got[0] != "admins" || got[1] != "users" {
				t.Errorf("groups = %v", got)
			}
			if got := a.Attributes.Get("urn:oid:0.9.2342.19200300.100.1.3"); got != "alice@example.com" {
				t.Errorf("mail = %q", got)
			}
			if len(a.Attributes) != 2 {
				t.Errorf("attributes = %+v", a.Attributes)
			}
			if len(a.SessionIndexes) != 1 || a.SessionIndexes[0] != "session-1" {
				t.Errorf("SessionIndexes = %v", a.SessionIndexes)
			}
			if a.AuthnContextClassRef != saml.AuthnContextPasswordProtectedTransport {
				t.Errorf("AuthnContextClassRef = %q", a.AuthnContextClassRef)
			}
			if !a.AuthnInstant.Equal(testSubject.AuthnInstant.Truncate(time.Millisecond)) && !a.AuthnInstant.Equal(testSubject.AuthnInstant) {
				t.Errorf("AuthnInstant = %v, want %v", a.AuthnInstant, testSubject.AuthnInstant)
			}
		})
	}
}

// TestSignedRequestReplay checks that a signed request, with whichever
// binding carries its signature, is accepted only once, and that an
// unsigned one is not recorded.
func TestSignedRequestReplay(t *testing.T) {
	ctx := context.Background()
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			p := newPair(t, nil, []samlsp.Option{samlsp.SignAuthnRequests})
			msg, err := p.sp.AuthnRequest(ctx, "", samlsp.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			if msg.Binding != binding {
				t.Fatalf("Binding = %s", msg.Binding)
			}
			if _, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg)); err != nil {
				t.Fatal(err)
			}
			_, err = p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg))
			if !errors.Is(err, saml.ErrAssertionReplayed) {
				t.Fatalf("replayed signed request: got %v", err)
			}
		})
	}

	// An unsigned request is not recorded.
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run("unsigned "+binding, func(t *testing.T) {
			p := newPair(t, nil, nil)
			msg, err := p.sp.AuthnRequest(ctx, "", samlsp.WithBinding(binding))
			if err != nil {
				t.Fatal(err)
			}
			for range 2 {
				if _, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg)); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}

func TestUnsignedRequestRefused(t *testing.T) {
	p := newPair(t, []samlidp.Option{samlidp.RequireSignedAuthnRequests}, nil)
	msg, err := p.sp.AuthnRequest(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.idp.ParseAuthnRequest(context.Background(), browserRequest(t, msg))
	if !errors.Is(err, saml.ErrInvalidSignature) {
		t.Fatalf("got %v", err)
	}
	md := p.idp.Metadata()
	if w := md.IDPSSODescriptors[0].WantAuthnRequestsSigned; w == nil || !*w {
		t.Error("the metadata does not say WantAuthnRequestsSigned")
	}
}

// TestKeptRequest stores the AuthnRequest as JSON, as an application does
// while the user logs in, and answers it after the request has expired.
func TestKeptRequest(t *testing.T) {
	keys(t)
	now := time.Now()
	later := now.Add(10 * time.Minute) // the user takes ten minutes to log in
	p := newPair(t, []samlidp.Option{samlidp.WithClock(dsig.NewFakeClockAt(now))}, nil)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "rs", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509))
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var kept samlidp.AuthnRequest
	if err := json.Unmarshal(buf, &kept); err != nil {
		t.Fatal(err)
	}
	if len(kept.AuthnContextClasses) != 1 || kept.AuthnContextClasses[0] != saml.AuthnContextX509 || kept.NameIDFormat != saml.TransientNameIDFormat {
		t.Fatalf("kept %+v", kept)
	}

	idpLater, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(p.sp.Metadata(ctx)),
		samlidp.WithSigningKey(idpKey, idpCert), samlidp.WithClock(dsig.NewFakeClockAt(later)))
	if err != nil {
		t.Fatal(err)
	}
	_, err = idpLater.ParseAuthnRequest(ctx, browserRequest(t, msg))
	if !errors.Is(err, saml.ErrExpired) {
		t.Fatalf("parsing the request again: got %v, want expired", err)
	}

	subject := testSubject
	subject.AuthnContextClassRef = saml.AuthnContextX509
	subject.AuthnInstant = later.Add(-time.Minute)
	resp, err := idpLater.Response(ctx, &kept, subject)
	if err != nil {
		t.Fatal(err)
	}
	spLater, err := samlsp.New(spEntityID, func(context.Context) (*saml.EntityDescriptor, error) { return idpLater.Metadata(), nil },
		samlsp.WithSigningKey(spKey, spCert), samlsp.WithClock(dsig.NewFakeClockAt(later)))
	if err != nil {
		t.Fatal(err)
	}
	a, err := spLater.ParseResponse(ctx, postForm(t, resp.Destination, formOf(t, resp)),
		samlsp.WithRequestID(msg.ID), samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509))
	if err != nil {
		t.Fatal(err)
	}
	if a.AuthnContextClassRef != saml.AuthnContextX509 {
		t.Fatalf("got %+v", a)
	}
}

func TestSimpleSignResponse(t *testing.T) {
	// The SP lists an ACS with the HTTP-POST-SimpleSign binding.
	p := newPair(t, nil, []samlsp.Option{samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.AssertionConsumerServiceBindings = []string{saml.HTTPPostBinding, saml.HTTPArtifactBinding, saml.HTTPPostSimpleSignBinding}
	})})
	ctx := context.Background()
	msg, req, err := p.parse(t, samlsp.WithResponseBinding(saml.HTTPPostSimpleSignBinding))
	if err != nil {
		t.Fatal(err)
	}
	if req.ACSBinding != saml.HTTPPostSimpleSignBinding {
		t.Fatalf("ACSBinding = %q", req.ACSBinding)
	}
	resp, err := p.idp.Response(ctx, req, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	fields := resp.FormValues()
	if resp.Binding != saml.HTTPPostSimpleSignBinding || fields["SigAlg"] == "" || fields["Signature"] == "" {
		t.Fatalf("got %+v, %v", resp, fields)
	}
	a, err := p.deliver(t, resp, samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != testSubject.NameID {
		t.Fatalf("got %+v", a)
	}
}
