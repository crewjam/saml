package samlsp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestWithSignatureMethod(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.WantAuthnRequestsSigned = true
	cfg := newTestConfig(t, ti, samlsp.SignAuthnRequests, samlsp.SignMetadata,
		samlsp.WithSignatureMethod(dsig.RSASHA512SignatureMethod))

	// AuthnRequest, which the IdP verifies.
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.RedirectURL().Query().Get("SigAlg"); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("AuthnRequest SigAlg = %s", got)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}

	// Signed metadata.
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	if !strings.Contains(w.Body.String(), `Algorithm="`+dsig.RSASHA512SignatureMethod+`"`) {
		t.Errorf("metadata is not signed with RSA-SHA512: %.300s", w.Body.String())
	}
	// The metadata still says AuthnRequests are signed only when they are.
	unsigned := newTestConfig(t, ti, samlsp.WithSignatureMethod(dsig.RSASHA512SignatureMethod))
	if md := unsigned.Metadata(t.Context()); *md.SPSSODescriptors[0].AuthnRequestsSigned {
		t.Error("AuthnRequestsSigned without SignAuthnRequests")
	}
	msg, err = unsigned.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if msg.RedirectURL().Query().Get("Signature") != "" {
		t.Error("an AuthnRequest was signed without SignAuthnRequests")
	}
}

func TestWithSignatureMethodErrors(t *testing.T) {
	ti := newTestIDP(t)
	rsaKey, rsaCert := newKeyPair(t, "rsa")
	ecKey, ecCert := newECKeyPair(t)
	for name, opts := range map[string][]samlsp.Option{
		"no key":      {samlsp.WithSignatureMethod(dsig.RSASHA256SignatureMethod)},
		"RSA with EC": {samlsp.WithSigningKey(ecKey, ecCert), samlsp.WithSignatureMethod(dsig.RSASHA256SignatureMethod)},
		"EC with RSA": {samlsp.WithSigningKey(rsaKey, rsaCert), samlsp.WithSignatureMethod(dsig.ECDSASHA256SignatureMethod)},
		"SHA-1":       {samlsp.WithSigningKey(rsaKey, rsaCert), samlsp.WithSignatureMethod(dsig.RSASHA1SignatureMethod)},
		"unknown":     {samlsp.WithSigningKey(rsaKey, rsaCert), samlsp.WithSignatureMethod("rot13")},
	} {
		if _, err := samlsp.New(spEntityID, staticIDP(ti), opts...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(ecKey, ecCert),
		samlsp.WithSignatureMethod(dsig.ECDSASHA384SignatureMethod)); err != nil {
		t.Errorf("ECDSA-SHA384 with an EC key: %v", err)
	}
}

// TestGeneralSignatureMethod checks that messages other than logout
// messages are signed with the method of WithSignatureMethod, not with a
// LogoutSignatureMethod set for logout messages only.
func TestGeneralSignatureMethod(t *testing.T) {
	ti := newTestIDP(t)
	aa := newAttributeAuthority(t, ti)
	logoutOnly := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.LogoutSignatureMethod = dsig.RSASHA256SignatureMethod
	})
	cfg := newTestConfigWithIDP(t, ti, withAttributeService(ti, aa.URL), samlsp.WithHTTPClient(aa.Client()),
		samlsp.WithSignatureMethod(dsig.RSASHA512SignatureMethod), logoutOnly)

	alice := saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "alice@example.com"}
	if _, err := cfg.QueryAttributes(t.Context(), alice); err != nil {
		t.Fatal(err)
	}
	if aa.sigAlg != dsig.RSASHA512SignatureMethod {
		t.Errorf("AttributeQuery signed with %q", aa.sigAlg)
	}
	if got := signedWith(t, cfg); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("SignElement signed with %q", got)
	}

	// SignatureMethod, when set, is the general method.
	if got := signedWith(t, cfg, samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.SignatureMethod = dsig.RSASHA384SignatureMethod
	})); got != dsig.RSASHA384SignatureMethod {
		t.Errorf("SignElement with SignatureMethod signed with %q", got)
	}

	// A key that does not suit WithSignatureMethod is used with SHA-256.
	ecKey, ecCert := newECKeyPair(t)
	if got := signedWith(t, cfg, samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.Key, sp.Certificate = ecKey, ecCert
	})); got != dsig.ECDSASHA256SignatureMethod {
		t.Errorf("SignElement with an ECDSA key signed with %q", got)
	}
}

// signedWith returns the signature method of an element signed by cfg.
func signedWith(t *testing.T, cfg *samlsp.Config, opts ...samlsp.ServiceProviderOption) string {
	t.Helper()
	el := etree.NewElement("Test")
	el.CreateAttr("ID", "id-test")
	signed, err := cfg.SignElement(el, opts...)
	if err != nil {
		t.Fatal(err)
	}
	m := signed.FindElement(".//SignatureMethod")
	if m == nil {
		t.Fatal("not signed")
	}
	return m.SelectAttrValue("Algorithm", "")
}

// A ServiceProviderOption that sets SignatureMethod makes the metadata say
// AuthnRequestsSigned="true", so the AuthnRequests are signed too.
func TestServiceProviderSignatureMethodSignsAuthnRequests(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.WantAuthnRequestsSigned = true
	cfg := newTestConfig(t, ti, samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.SignatureMethod = dsig.RSASHA512SignatureMethod
	}))
	if md := cfg.Metadata(t.Context()); !*md.SPSSODescriptors[0].AuthnRequestsSigned {
		t.Fatal("the metadata does not say AuthnRequestsSigned")
	}
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.RedirectURL().Query().Get("SigAlg"); got != dsig.RSASHA512SignatureMethod {
		t.Fatalf("AuthnRequest SigAlg = %q", got)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatal(err)
	}
}

// A signing key without its certificate could sign nothing the IdP can
// verify, and the metadata would publish no signing key.
func TestSigningKeyWithoutCertificate(t *testing.T) {
	ti := newTestIDP(t)
	key, _ := newKeyPair(t, "sp")
	if _, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(key, nil)); err == nil {
		t.Fatal("New accepted WithSigningKey without a certificate")
	}
}
