package samlsp_test

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

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

	// LogoutRequest.
	msg, err = cfg.LogoutRequest(t.Context(), saml.NameID{Value: "alice"}, "s")
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.RedirectURL().Query().Get("SigAlg"); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("LogoutRequest SigAlg = %s", got)
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
		"RSA with EC": {samlsp.WithKey(ecKey, ecCert), samlsp.WithSignatureMethod(dsig.RSASHA256SignatureMethod)},
		"EC with RSA": {samlsp.WithKey(rsaKey, rsaCert), samlsp.WithSignatureMethod(dsig.ECDSASHA256SignatureMethod)},
		"SHA-1":       {samlsp.WithKey(rsaKey, rsaCert), samlsp.WithSignatureMethod(dsig.RSASHA1SignatureMethod)},
		"unknown":     {samlsp.WithKey(rsaKey, rsaCert), samlsp.WithSignatureMethod("rot13")},
	} {
		if _, err := samlsp.New(staticIDP(ti), spEntityID, opts...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
	if _, err := samlsp.New(staticIDP(ti), spEntityID, samlsp.WithKey(ecKey, ecCert),
		samlsp.WithSignatureMethod(dsig.ECDSASHA384SignatureMethod)); err != nil {
		t.Errorf("ECDSA-SHA384 with an EC key: %v", err)
	}
}
