package samlsp_test

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// parseIDPInitiated parses the IdP-initiated response of the fixtures with
// a Config made with opts, passing respOpts to ParseResponse.
func parseIDPInitiated(t *testing.T, opts []samlsp.Option, respOpts ...samlsp.ResponseOption) (*samlsp.Assertion, error) {
	t.Helper()
	const name = "Entra ID, IdP-initiated"
	var fx *idpFixture
	for i := range idpFixtures {
		if idpFixtures[i].name == name {
			fx = &idpFixtures[i]
		}
	}
	if fx == nil {
		t.Fatalf("no fixture %q", name)
	}
	key, cert := fixtureKeyPair(t)
	opts = append([]samlsp.Option{
		samlsp.WithACSURL(fx.acsURL),
		samlsp.WithKey(key, cert),
		samlsp.WithClock(dsig.NewFakeClockAt(fx.now)),
	}, opts...)
	cfg, err := samlsp.New(samlsp.StaticMetadataBytes(coreTestdata(t, fx.metadata)), fx.entityID, opts...)
	if err != nil {
		t.Fatal(err)
	}
	response := base64.StdEncoding.EncodeToString(coreTestdata(t, fx.response))
	r := httptest.NewRequest(http.MethodPost, fx.acsURL, strings.NewReader(url.Values{"SAMLResponse": {response}}.Encode()))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	return cfg.ParseResponse(t.Context(), r, respOpts...)
}

// TestParseResponseKeepsServiceProviderSettings checks that ParseResponse
// overrides AllowIDPInitiated and RequestedAuthnContext only when its own
// options set them, so settings made with WithServiceProvider hold.
func TestParseResponseKeepsServiceProviderSettings(t *testing.T) {
	allowIDPInitiated := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.AllowIDPInitiated = true })
	if _, err := parseIDPInitiated(t, []samlsp.Option{allowIDPInitiated}); err != nil {
		t.Errorf("AllowIDPInitiated from New: %v (%v)", err, errors.Unwrap(err))
	}
	if _, err := parseIDPInitiated(t, nil); !errors.Is(err, samlsp.ErrNoRequestID) {
		t.Errorf("without AllowIDPInitiated: err = %v, want ErrNoRequestID", err)
	}

	// The response's class is PasswordProtectedTransport.
	requireKerberos := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
		sp.RequestedAuthnContext = &saml.RequestedAuthnContext{
			Comparison:            string(samlsp.ComparisonExact),
			AuthnContextClassRefs: []string{string(samlsp.AuthnContextKerberos)},
		}
	})
	if _, err := parseIDPInitiated(t, []samlsp.Option{requireKerberos}, samlsp.AllowUnsolicited); err == nil {
		t.Error("the RequestedAuthnContext set with WithServiceProvider was dropped")
	}
	// An AuthnContextOption of the call takes precedence.
	if _, err := parseIDPInitiated(t, []samlsp.Option{requireKerberos}, samlsp.AllowUnsolicited,
		samlsp.WithAuthnContext(samlsp.ComparisonExact, samlsp.AuthnContextPasswordProtectedTransport)); err != nil {
		t.Errorf("with the call's AuthnContextOption: %v (%v)", err, errors.Unwrap(err))
	}
}

// signatureAlgorithm returns the SignatureMethod of the signature in a
// signed XML message.
func signatureAlgorithm(t *testing.T, xmlText string) string {
	t.Helper()
	doc := etree.NewDocument()
	if err := doc.ReadFromString(xmlText); err != nil {
		t.Fatal(err)
	}
	m := doc.FindElement("//Signature/SignedInfo/SignatureMethod")
	if m == nil {
		return ""
	}
	return m.SelectAttrValue("Algorithm", "")
}

// TestSendSignsWithCallServiceProvider checks that messages are signed
// with the method of the call's ServiceProvider, as its options leave it.
func TestSendSignsWithCallServiceProvider(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.SignAuthnRequests)
	sha512 := samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.SignatureMethod = dsig.RSASHA512SignatureMethod })

	msg, err := cfg.AuthnRequest(t.Context(), "s", sha512)
	if err != nil {
		t.Fatal(err)
	}
	if got := msg.RedirectURL().Query().Get("SigAlg"); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("HTTP-Redirect SigAlg = %s", got)
	}

	msg, err = cfg.AuthnRequest(t.Context(), "s", sha512, samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	if got := signatureAlgorithm(t, decodeFormMessage(t, w.Body.String(), "SAMLRequest")); got != dsig.RSASHA512SignatureMethod {
		t.Errorf("HTTP-POST SignatureMethod = %s", got)
	}
}

// TestSignElementOptions checks that SignElement applies the
// ServiceProviderOptions of New, then its own.
func TestSignElementOptions(t *testing.T) {
	ti := newTestIDP(t)
	method := func(m string) samlsp.ServiceProviderOption {
		return samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.LogoutSignatureMethod = m })
	}
	cfg := newTestConfig(t, ti, method(dsig.RSASHA384SignatureMethod))
	el := etree.NewElement("Thing")
	el.CreateAttr("ID", "id-thing")

	for want, opts := range map[string][]samlsp.ServiceProviderOption{
		dsig.RSASHA384SignatureMethod: nil,
		dsig.RSASHA512SignatureMethod: {method(dsig.RSASHA512SignatureMethod)},
	} {
		signed, err := cfg.SignElement(el, opts...)
		if err != nil {
			t.Fatal(err)
		}
		doc := etree.NewDocument()
		doc.SetRoot(signed)
		s, _ := doc.WriteToString()
		if got := signatureAlgorithm(t, s); got != want {
			t.Errorf("SignatureMethod = %s, want %s", got, want)
		}
	}
}

func TestMetadataXML(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	unsigned, err := cfg.MetadataXML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(unsigned), "SignatureValue") {
		t.Error("signed without SignMetadata")
	}
	signed, err := cfg.MetadataXML(t.Context(), samlsp.SignMetadata)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(signed), "SignatureValue") {
		t.Error("not signed with SignMetadata")
	}

	// It is what ServeMetadata serves.
	cfg = newTestConfig(t, ti, samlsp.SignMetadata)
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	buf, err := cfg.MetadataXML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if signatureAlgorithm(t, w.Body.String()) == "" || signatureAlgorithm(t, string(buf)) != signatureAlgorithm(t, w.Body.String()) {
		t.Error("MetadataXML and ServeMetadata differ")
	}
}
