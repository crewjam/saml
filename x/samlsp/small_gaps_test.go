package samlsp_test

import (
	"crypto"
	"crypto/rsa"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

func TestWithNameIDFormat(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, samlsp.WithNameIDFormat(saml.PersistentNameIDFormat))
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	req := decodeRedirectRequest(t, msg.RedirectURL())
	if p := req.NameIDPolicy; p == nil || p.Format == nil || *p.Format != string(saml.PersistentNameIDFormat) {
		t.Errorf("NameIDPolicy = %+v", req.NameIDPolicy)
	}
	if f := cfg.Metadata(t.Context()).SPSSODescriptors[0].NameIDFormats; len(f) == 0 || f[0] != saml.PersistentNameIDFormat {
		t.Errorf("metadata NameIDFormats = %v", f)
	}
}

func TestMessageServeHTTP(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	// A Message is an http.Handler.
	var h http.Handler = msg
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/login", nil))
	if w.Code != http.StatusFound || w.Header().Get("Location") != msg.RedirectURL().String() {
		t.Errorf("%d %s", w.Code, w.Header().Get("Location"))
	}
}

func TestQueryAttributesServiceProviderOption(t *testing.T) {
	ti := newTestIDP(t)
	aa := newAttributeAuthority(t, ti)
	cfg := newTestConfigWithIDP(t, ti, withAttributeService(ti, aa.URL), samlsp.WithHTTPClient(aa.Client()))
	called := false
	_, err := cfg.QueryAttributes(t.Context(), saml.NameID{Value: "alice@example.com"},
		samlsp.WithServiceProvider(func(*saml.ServiceProvider) { called = true }))
	if err != nil {
		t.Fatal(err)
	}
	if !called {
		t.Error("the ServiceProviderOption was not applied")
	}
}

// failingSigner is an RSA key whose signing always fails, as an HSM that is
// unavailable would.
type failingSigner struct{ *rsa.PrivateKey }

func (failingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("HSM unavailable")
}

func TestServeMetadataSigningFails(t *testing.T) {
	ti := newTestIDP(t)

	// SignMetadata without a key is refused at once.
	if _, err := samlsp.New(staticIDP(ti), spEntityID, samlsp.SignMetadata); err == nil {
		t.Error("SignMetadata without a key was accepted")
	}

	// A key that fails when it signs: the metadata endpoint answers 500.
	key, cert := newKeyPair(t, "sp")
	cfg, err := samlsp.New(staticIDP(ti), spEntityID, samlsp.WithKey(failingSigner{key}, cert), samlsp.SignMetadata)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	if w.Code != http.StatusInternalServerError {
		t.Errorf("%d %s", w.Code, w.Body.String())
	}
}

// TestNameIDPolicyOptionsWithoutPolicy: WithAllowCreate and
// WithSPNameQualifier make a NameIDPolicy if an earlier option removed it.
func TestNameIDPolicyOptionsWithoutPolicy(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	removePolicy := samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		req.NameIDPolicy = nil
		return nil
	})
	for name, opt := range map[string]samlsp.AuthnOption{
		"WithAllowCreate":     samlsp.WithAllowCreate(false),
		"WithSPNameQualifier": samlsp.WithSPNameQualifier("https://affiliation.example.com"),
	} {
		msg, err := cfg.AuthnRequest(t.Context(), "s", removePolicy, opt)
		if err != nil {
			t.Fatal(err)
		}
		if req := decodeRedirectRequest(t, msg.RedirectURL()); req.NameIDPolicy == nil {
			t.Errorf("%s did not make a NameIDPolicy", name)
		}
	}
}
