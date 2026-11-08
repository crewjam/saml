package samlsp_test

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// coreTestdata reads a file of package saml's testdata, which holds
// responses in the wire formats of real IdPs.
func coreTestdata(t *testing.T, name string) []byte {
	t.Helper()
	buf, err := os.ReadFile(filepath.Join("..", "..", "testdata", name)) //nolint:gosec // G304: fixture names are constants of this test
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

func fixtureKeyPair(t *testing.T) (crypto.Signer, *x509.Certificate) {
	t.Helper()
	keyBlock, _ := pem.Decode(coreTestdata(t, "sp_key.pem"))
	key, err := x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
	if err != nil {
		k, err2 := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
		if err2 != nil {
			t.Fatal(err)
		}
		key = k.(*rsa.PrivateKey)
	}
	certBlock, _ := pem.Decode(coreTestdata(t, "sp_cert.pem"))
	cert, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

type idpFixture struct {
	name      string
	metadata  string // file in core testdata
	response  string // file in core testdata
	base64    bool   // response file holds base64 already
	entityID  string
	acsURL    string
	now       time.Time
	requestID string // "" for an unsolicited response
	subject   string
	attribute string // an attribute Name the response carries
	value     string // its first value

	// For a response the default hardening refuses: the error it is
	// refused with, and the ServiceProviderOption that accepts it.
	refusedWith error
	relax       samlsp.ServiceProviderOption
}

// allowCBCInUnsignedResponse accepts an AES-CBC encrypted assertion in an
// unsigned Response, as IdPs that sign only the assertion send.
var allowCBCInUnsignedResponse = samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
	sp.RequireSignedResponseForCBC = false
})

// allowSHA1 accepts SHA-1 signatures, as older IdPs make.
var allowSHA1 = samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) {
	sp.RejectSHA1Signatures = false
})

var idpFixtures = []idpFixture{
	{
		name: "Entra ID, assertion signed", metadata: "TestSPCanHandleEntraIDResponse_IDPMetadata",
		response: "TestSPCanHandleEntraIDResponse_assertion_signed",
		entityID: "https://sp.example.com/saml/metadata", acsURL: "https://sp.example.com/saml/acs",
		now: time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC), requestID: "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f",
		subject: "alice@contoso.example", attribute: "http://schemas.microsoft.com/identity/claims/displayname", value: "Alice Example",
	},
	{
		name: "Entra ID, response signed", metadata: "TestSPCanHandleEntraIDResponse_IDPMetadata",
		response: "TestSPCanHandleEntraIDResponse_response_signed",
		entityID: "https://sp.example.com/saml/metadata", acsURL: "https://sp.example.com/saml/acs",
		now: time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC), requestID: "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f",
		subject: "alice@contoso.example", attribute: "http://schemas.microsoft.com/identity/claims/displayname", value: "Alice Example",
	},
	{
		name: "Entra ID, response and assertion signed", metadata: "TestSPCanHandleEntraIDResponse_IDPMetadata",
		response: "TestSPCanHandleEntraIDResponse_response_and_assertion_signed",
		entityID: "https://sp.example.com/saml/metadata", acsURL: "https://sp.example.com/saml/acs",
		now: time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC), requestID: "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f",
		subject: "alice@contoso.example", attribute: "http://schemas.microsoft.com/identity/claims/displayname", value: "Alice Example",
	},
	{
		name: "Entra ID, encrypted", metadata: "TestSPCanHandleEntraIDResponse_IDPMetadata",
		response: "TestSPCanHandleEntraIDResponse_encrypted_assertion_signed",
		entityID: "https://sp.example.com/saml/metadata", acsURL: "https://sp.example.com/saml/acs",
		now: time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC), requestID: "id-4f6e2c9d8a7b1e3f5d0c2b4a6e8f1d3c5b7a9e0f",
		subject: "alice@contoso.example", attribute: "http://schemas.microsoft.com/identity/claims/displayname", value: "Alice Example",
		// Entra signs the assertion and encrypts it with AES-CBC.
		refusedWith: saml.ErrInvalidSignature, relax: allowCBCInUnsignedResponse,
	},
	{
		name: "Entra ID, IdP-initiated", metadata: "TestSPCanHandleEntraIDResponse_IDPMetadata",
		response: "TestSPCanHandleEntraIDResponse_idp_initiated",
		entityID: "https://sp.example.com/saml/metadata", acsURL: "https://sp.example.com/saml/acs",
		now:     time.Date(2025, 6, 2, 15, 4, 6, 0, time.UTC),
		subject: "alice@contoso.example", attribute: "http://schemas.microsoft.com/identity/claims/displayname", value: "Alice Example",
	},
	{
		name: "Okta, signed response, encrypted assertion", metadata: "TestSPCanHandleOktaSignedResponseEncryptedAssertion_IDPMetadata",
		response: "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response", base64: true,
		entityID: "http://localhost:8000/saml/metadata", acsURL: "http://localhost:8000/saml/acs",
		now: time.Date(2020, 3, 3, 19, 24, 28, 0, time.UTC), requestID: "id-a7364d1e4432aa9085a7a8bd824ea2fa8fa8f684",
		subject: "testuser@testrsc.com", attribute: "Username", value: "FixedValue",
	},
	{
		name: "Okta, encrypted signed assertion", metadata: "TestSPCanHandleOktaResponseEncryptedSignedAssertion_IDPMetadata",
		response: "TestSPCanHandleOktaResponseEncryptedSignedAssertion_response", base64: true,
		entityID: "http://localhost:8000/saml/metadata", acsURL: "http://localhost:8000/saml/acs",
		now: time.Date(2020, 3, 3, 19, 31, 55, 0, time.UTC), requestID: "id-6d976cdde8e76df5df0a8ff58148fc0b7ec6796d",
		subject: "testuser@testrsc.com", attribute: "Username", value: "FixedValue",
		refusedWith: saml.ErrInvalidSignature, relax: allowCBCInUnsignedResponse,
	},
	{
		name: "OneLogin", metadata: "TestSPCanHandleOneloginResponse_IDPMetadata",
		response: "TestSPCanHandleOneloginResponse_response", base64: true,
		entityID: "https://29ee6d2e.ngrok.io/saml/metadata", acsURL: "https://29ee6d2e.ngrok.io/saml/acs",
		now: time.Date(2016, 1, 5, 17, 53, 12, 0, time.UTC), requestID: "id-d40c15c104b52691eccf0a2a5c8a15595be75423",
		subject: "ross@kndr.org", attribute: "User.email", value: "ross@kndr.org",
		refusedWith: saml.ErrUnsupported, relax: allowSHA1,
	},
}

// TestIDPFixtures runs responses in the wire formats of real IdPs through
// ParseResponse. Those that the default hardening refuses must be refused
// for the expected reason, and accepted once only that is relaxed.
func TestIDPFixtures(t *testing.T) {
	key, cert := fixtureKeyPair(t)
	for _, fx := range idpFixtures {
		t.Run(fx.name, func(t *testing.T) {
			parse := func(opts ...samlsp.Option) (*samlsp.Assertion, error) {
				opts = append([]samlsp.Option{
					samlsp.WithACSURL(fx.acsURL),
					samlsp.WithSigningKey(key, cert),
					samlsp.WithEncryptionKey(key.(*rsa.PrivateKey), cert),
					samlsp.WithClock(dsig.NewFakeClockAt(fx.now)),
				}, opts...)
				cfg, err := samlsp.New(fx.entityID, samlsp.StaticMetadataBytes(coreTestdata(t, fx.metadata)), opts...)
				if err != nil {
					t.Fatal(err)
				}
				response := coreTestdata(t, fx.response)
				if !fx.base64 {
					response = []byte(base64.StdEncoding.EncodeToString(response))
				}
				r := httptest.NewRequest(http.MethodPost, fx.acsURL,
					strings.NewReader(url.Values{"SAMLResponse": {strings.TrimSpace(string(response))}}.Encode()))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				opt := samlsp.WithRequestID(fx.requestID)
				if fx.requestID == "" {
					opt = samlsp.AllowUnsolicited
				}
				return cfg.ParseResponse(t.Context(), r, opt)
			}

			if fx.refusedWith != nil {
				if _, err := parse(); !errors.Is(err, fx.refusedWith) {
					t.Fatalf("with the default hardening: err = %v (%v), want %v", err, errors.Unwrap(err), fx.refusedWith)
				}
				a, err := parse(fx.relax)
				if err != nil {
					t.Fatalf("relaxed: %v (%v)", err, errors.Unwrap(err))
				}
				fx.check(t, a)
				return
			}
			a, err := parse()
			if err != nil {
				t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
			}
			fx.check(t, a)
		})
	}
}

func (fx idpFixture) check(t *testing.T, a *samlsp.Assertion) {
	t.Helper()
	if a.Subject != fx.subject || a.Attributes.Get(fx.attribute) != fx.value {
		t.Errorf("subject %q, %s = %q", a.Subject, fx.attribute, a.Attributes.Get(fx.attribute))
	}
}
