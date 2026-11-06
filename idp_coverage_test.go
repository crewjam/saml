package saml

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"html/template"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

// idpcovNewTest wraps NewIdentityProviderTest and restores the package globals
// it mutates once the test finishes.
func idpcovNewTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
	t.Cleanup(func() {
		TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader
	})
	return NewIdentityProviderTest(t, applyKey)
}

// idpcovFailingResponseWriter is an http.ResponseWriter whose Write always fails.
type idpcovFailingResponseWriter struct {
	header http.Header
	code   int
}

func (w *idpcovFailingResponseWriter) Header() http.Header {
	if w.header == nil {
		w.header = http.Header{}
	}
	return w.header
}

func (w *idpcovFailingResponseWriter) Write([]byte) (int, error) {
	return 0, errors.New("idpcov: write failed")
}

func (w *idpcovFailingResponseWriter) WriteHeader(code int) { w.code = code }

// idpcovFailingSigner exposes a valid public key but always fails to sign.
type idpcovFailingSigner struct {
	crypto.Signer
}

func (idpcovFailingSigner) Sign(io.Reader, []byte, crypto.SignerOpts) ([]byte, error) {
	return nil, errors.New("idpcov: sign failed")
}

// idpcovAssertionMakerFunc adapts a function to the AssertionMaker interface.
type idpcovAssertionMakerFunc func(req *IdpAuthnRequest, session *Session) error

func (f idpcovAssertionMakerFunc) MakeAssertion(req *IdpAuthnRequest, session *Session) error {
	return f(req, session)
}

func idpcovAliceSession(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
	return &Session{ID: "f00df00df00d", UserName: "alice"}
}

func idpcovSSORequest(t *testing.T, test *IdentityProviderTest) *http.Request {
	t.Helper()
	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	r, err := http.NewRequest("GET", requestURL.String(), nil)
	assert.NilError(t, err)
	return r
}

// idpcovRequest returns a request ready for MakeAssertion / MakeAssertionEl /
// MakeResponse, without going through Validate.
func idpcovRequest(t *testing.T, test *IdentityProviderTest) *IdpAuthnRequest {
	t.Helper()
	r, err := http.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
	assert.NilError(t, err)
	r.RemoteAddr = "192.0.2.1"
	return &IdpAuthnRequest{
		IDP:                     &test.IDP,
		HTTPRequest:             r,
		Now:                     TimeNow(),
		Request:                 AuthnRequest{ID: "id-123", IssueInstant: TimeNow()},
		ServiceProviderMetadata: &EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata"},
		SPSSODescriptor:         &SPSSODescriptor{},
		ACSEndpoint:             &IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp.example.com/saml2/acs"},
	}
}

func idpcovCertKeyDescriptor(use string, data string) KeyDescriptor {
	return KeyDescriptor{
		Use: use,
		KeyInfo: KeyInfo{X509Data: X509Data{
			X509Certificates: []X509Certificate{{Data: data}},
		}},
	}
}

func idpcovECDSACert(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "ecdsa.example.com"},
		NotBefore:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	assert.NilError(t, err)
	return base64.StdEncoding.EncodeToString(der)
}

func TestIDPCovMetadataValidDurationAndLogout(t *testing.T) {
	test := idpcovNewTest(t)
	d := 2 * time.Hour
	test.IDP.ValidDuration = &d
	test.IDP.LogoutURL = mustParseURL("https://idp.example.com/saml/logout")

	md := test.IDP.Metadata()
	assert.Check(t, is.Equal(d, md.CacheDuration))
	assert.Check(t, is.Equal(TimeNow().Add(d), md.ValidUntil))
	assert.Check(t, is.DeepEqual([]Endpoint{{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/saml/logout"}},
		md.IDPSSODescriptors[0].SingleLogoutServices))
}

func TestIDPCovServeMetadataWriteError(t *testing.T) {
	test := idpcovNewTest(t)
	w := &idpcovFailingResponseWriter{}
	r := httptest.NewRequest("GET", "https://idp.example.com/saml/metadata", nil)
	test.IDP.ServeMetadata(w, r)
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.code))
}

func TestIDPCovServeSSOMakeAssertionError(t *testing.T) {
	test := idpcovNewTest(t)
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return errors.New("no assertion for you")
	})

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestIDPCovServeSSOWriteResponseError(t *testing.T) {
	test := idpcovNewTest(t)
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
	test.IDP.SignatureMethod = "urn:idpcov:bogus-signature-method"

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestIDPCovServeIDPInitiatedErrors(t *testing.T) {
	t.Run("service provider lookup error", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
				return nil, errors.New("database on fire")
			},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})

	t.Run("no POST ACS endpoint", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
				return &EntityDescriptor{
					EntityID: "https://sp.example.com/saml2/metadata",
					SPSSODescriptors: []SPSSODescriptor{
						{AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPArtifactBinding, Location: "https://sp.example.com/acs"}}},
						{},
					},
				}, nil
			},
		}
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})

	t.Run("assertion maker error", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
		test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
			return errors.New("no assertion for you")
		})
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})

	t.Run("write response error", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
		test.IDP.SignatureMethod = "urn:idpcov:bogus-signature-method"
		w := httptest.NewRecorder()
		r := httptest.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
		test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
		assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
	})
}

func TestIDPCovNewIdpAuthnRequestBadPostForm(t *testing.T) {
	test := idpcovNewTest(t)
	r := httptest.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader("SAMLRequest=%zz"))
	r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	_, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, err != nil)
}

func TestIDPCovValidateErrors(t *testing.T) {
	t.Run("wrong root element", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), RequestBuffer: []byte(`<NotAnAuthnRequest/>`)}
		assert.Check(t, is.ErrorContains(req.Validate(), "expected element type <AuthnRequest>"))
	})

	t.Run("service provider lookup error", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) {
				return nil, errors.New("database on fire")
			},
		}
		authnRequest, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		buf, err := xml.Marshal(authnRequest)
		assert.NilError(t, err)
		req := IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), RequestBuffer: buf}
		req.HTTPRequest = httptest.NewRequest("POST", "https://idp.example.com/saml/sso", nil)
		assert.Check(t, is.Error(req.Validate(),
			"cannot find service provider https://sp.example.com/saml2/metadata: database on fire"))
	})
}

func TestIDPCovGetACSEndpoint(t *testing.T) {
	yes, no := true, false
	post := IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp/post", Index: 1}
	redirect := IndexedEndpoint{Binding: HTTPRedirectBinding, Location: "https://sp/redirect", Index: 2}
	artifactDefault := IndexedEndpoint{Binding: HTTPArtifactBinding, Location: "https://sp/artifact", Index: 3, IsDefault: &yes}
	postNotDefault := IndexedEndpoint{Binding: HTTPPostBinding, Location: "https://sp/post-nd", Index: 4, IsDefault: &no}
	redirectDefault := IndexedEndpoint{Binding: HTTPRedirectBinding, Location: "https://sp/redirect-default", Index: 5, IsDefault: &yes}

	md := func(acs ...IndexedEndpoint) *EntityDescriptor {
		return &EntityDescriptor{SPSSODescriptors: []SPSSODescriptor{
			{},
			{AssertionConsumerServices: acs},
		}}
	}

	testCases := []struct {
		name     string
		request  AuthnRequest
		metadata *EntityDescriptor
		want     string // expected ACS location; "" means os.ErrNotExist
	}{
		{"index match", AuthnRequest{AssertionConsumerServiceIndex: "2"}, md(post, redirect), "https://sp/redirect"},
		{"index miss", AuthnRequest{AssertionConsumerServiceIndex: "9"}, md(post, redirect), ""},
		{"index miss, url match", AuthnRequest{AssertionConsumerServiceIndex: "9", AssertionConsumerServiceURL: "https://sp/post"}, md(post, redirect), "https://sp/post"},
		{"default redirect", AuthnRequest{}, md(postNotDefault, artifactDefault, redirectDefault), "https://sp/redirect-default"},
		{"no usable default, any binding", AuthnRequest{}, md(artifactDefault, postNotDefault), "https://sp/post-nd"},
		{"nothing usable", AuthnRequest{}, md(artifactDefault), ""},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			req := IdpAuthnRequest{Request: tc.request, ServiceProviderMetadata: tc.metadata}
			err := req.getACSEndpoint()
			if tc.want == "" {
				assert.Check(t, is.Equal(os.ErrNotExist, err))
				assert.Check(t, req.ACSEndpoint == nil)
				return
			}
			assert.NilError(t, err)
			assert.Check(t, is.Equal(tc.want, req.ACSEndpoint.Location))
			assert.Check(t, req.SPSSODescriptor != nil)
		})
	}
}

func TestIDPCovMakeAssertionExtraAttributes(t *testing.T) {
	test := idpcovNewTest(t)
	req := idpcovRequest(t, test)
	// No default AttributeConsumingService: the first one is used.
	req.SPSSODescriptor.AttributeConsumingServices = []AttributeConsumingService{
		{RequestedAttributes: []RequestedAttribute{{Attribute: Attribute{
			FriendlyName: "User ID",
			Name:         "user-id",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		}}}},
		{RequestedAttributes: []RequestedAttribute{{Attribute: Attribute{
			Name:       "email",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		}}}},
	}
	session := &Session{
		NameID:                "alice@example.com",
		NameIDFormat:          "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
		UserName:              "alice",
		UserScopedAffiliation: "member@example.com",
		SubjectID:             "alice-subject@example.com",
	}
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, session))

	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress", req.Assertion.Subject.NameID.Format))
	got := map[string]string{}
	for _, attr := range req.Assertion.AttributeStatements[0].Attributes {
		got[attr.Name] = attr.Values[0].Value
	}
	assert.Check(t, is.DeepEqual(map[string]string{
		"user-id":                                      "alice",
		"urn:oid:0.9.2342.19200300.100.1.1":            "alice",
		"urn:oid:1.3.6.1.4.1.5923.1.1.1.9":             "member@example.com",
		"urn:oasis:names:tc:SAML:attribute:subject-id": "alice-subject@example.com",
	}, got))
}

func idpcovMadeAssertion(t *testing.T, test *IdentityProviderTest) *IdpAuthnRequest {
	t.Helper()
	req := idpcovRequest(t, test)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{UserName: "alice"}))
	return req
}

func TestIDPCovMakeAssertionElErrors(t *testing.T) {
	t.Run("bad signature method", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SignatureMethod = "urn:idpcov:bogus-signature-method"
		req := idpcovMadeAssertion(t, test)
		assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "unknown SignatureMethod"))
	})

	t.Run("signer fails", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.Signer = idpcovFailingSigner{Signer: mustParsePrivateKey(golden.Get(t, "idp_key.pem"))}
		req := idpcovMadeAssertion(t, test)
		assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "idpcov: sign failed"))
	})

	t.Run("bad SP cert base64", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := idpcovMadeAssertion(t, test)
		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{idpcovCertKeyDescriptor("encryption", "!!!not base64!!!")}
		assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "cannot decode certificate base64"))
	})

	t.Run("bad SP cert DER", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := idpcovMadeAssertion(t, test)
		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{idpcovCertKeyDescriptor("encryption", "AAAA")}
		assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "cannot parse certificate"))
	})

	t.Run("SP cert is not RSA", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := idpcovMadeAssertion(t, test)
		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{idpcovCertKeyDescriptor("encryption", idpcovECDSACert(t))}
		assert.Check(t, is.ErrorContains(req.MakeAssertionEl(), "RSA public key"))
	})
}

func TestIDPCovGetSPEncryptionCert(t *testing.T) {
	test := idpcovNewTest(t)
	spCert := base64.StdEncoding.EncodeToString(test.SPCertificate.Raw)

	t.Run("unlabelled cert is used for encryption", func(t *testing.T) {
		req := idpcovMadeAssertion(t, test)
		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{
			idpcovCertKeyDescriptor("signing", spCert),
			{Use: ""}, // no certificates at all
			idpcovCertKeyDescriptor("", spCert),
		}
		cert, err := req.getSPEncryptionCert()
		assert.NilError(t, err)
		assert.Check(t, cert.Equal(test.SPCertificate))

		assert.NilError(t, req.MakeAssertionEl())
		assert.Check(t, is.Equal("saml:EncryptedAssertion", req.AssertionEl.FullTag()))
	})

	t.Run("encryption descriptor without certificates does not panic", func(t *testing.T) {
		req := idpcovMadeAssertion(t, test)
		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{
			{Use: "encryption"},
			idpcovCertKeyDescriptor("encryption", spCert),
		}
		cert, err := req.getSPEncryptionCert()
		assert.NilError(t, err)
		assert.Check(t, cert.Equal(test.SPCertificate))

		req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{{Use: "encryption"}}
		_, err = req.getSPEncryptionCert()
		assert.Check(t, is.Equal(os.ErrNotExist, err))
	})
}

func TestIDPCovPostBindingUnsupportedBinding(t *testing.T) {
	test := idpcovNewTest(t)
	req := idpcovRequest(t, test)
	req.ResponseEl = etree.NewElement("Response")
	req.ACSEndpoint.Binding = HTTPRedirectBinding
	_, err := req.PostBinding()
	assert.Check(t, is.Error(err, "https://sp.example.com/saml2/metadata: unsupported binding "+HTTPRedirectBinding))
}

func TestIDPCovWriteResponseErrors(t *testing.T) {
	t.Run("post binding error", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := idpcovRequest(t, test)
		req.ResponseEl = etree.NewElement("Response")
		req.ACSEndpoint.Binding = HTTPRedirectBinding
		assert.Check(t, is.ErrorContains(req.WriteResponse(httptest.NewRecorder()), "unsupported binding"))
	})

	t.Run("template error", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.ResponseFormTemplate = template.Must(template.New("idpcov").Parse(`{{.NoSuchField}}`))
		req := idpcovRequest(t, test)
		req.ResponseEl = etree.NewElement("Response")
		assert.Check(t, is.ErrorContains(req.WriteResponse(httptest.NewRecorder()), "NoSuchField"))
	})

	t.Run("write error", func(t *testing.T) {
		test := idpcovNewTest(t)
		req := idpcovRequest(t, test)
		req.ResponseEl = etree.NewElement("Response")
		assert.Check(t, is.Error(req.WriteResponse(&idpcovFailingResponseWriter{}), "idpcov: write failed"))
	})
}

func TestIDPCovMakeResponseErrors(t *testing.T) {
	t.Run("bad signature method", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.SignatureMethod = "urn:idpcov:bogus-signature-method"
		req := idpcovRequest(t, test)
		req.AssertionEl = etree.NewElement("Assertion")
		assert.Check(t, is.ErrorContains(req.MakeResponse(), "unknown SignatureMethod"))
	})

	t.Run("signer fails", func(t *testing.T) {
		test := idpcovNewTest(t)
		test.IDP.Signer = idpcovFailingSigner{Signer: mustParsePrivateKey(golden.Get(t, "idp_key.pem"))}
		req := idpcovRequest(t, test)
		req.AssertionEl = etree.NewElement("Assertion")
		assert.Check(t, is.ErrorContains(req.MakeResponse(), "idpcov: sign failed"))
	})
}

func TestIDPCovSigningContextIntermediates(t *testing.T) {
	test := idpcovNewTest(t)
	test.IDP.Intermediates = []*x509.Certificate{test.SPCertificate}
	req := idpcovMadeAssertion(t, test)
	assert.NilError(t, req.MakeResponse())

	// Both the leaf and the intermediate end up in the assertion's KeyInfo.
	certs := req.AssertionEl.FindElements("./Signature/KeyInfo/X509Data/X509Certificate")
	assert.Check(t, is.Len(certs, 2))
	assert.Check(t, is.Equal(base64.StdEncoding.EncodeToString(test.SPCertificate.Raw), certs[1].Text()))
}
