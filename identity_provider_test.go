package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"encoding/xml"
	"fmt"
	"io"
	"math/rand"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/beevik/etree"
	"github.com/golang-jwt/jwt/v4"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml/logger"
	"github.com/crewjam/saml/testsaml"
	"github.com/crewjam/saml/xmlenc"
)

type IdentityProviderTest struct {
	SPKey         *rsa.PrivateKey
	SPCertificate *x509.Certificate
	SP            ServiceProvider

	Key             crypto.PrivateKey
	Signer          crypto.Signer
	Certificate     *x509.Certificate
	SessionProvider SessionProvider
	IDP             IdentityProvider
}

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func mustParsePrivateKey(pemStr []byte) crypto.Signer {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	k, err := x509.ParsePKCS1PrivateKey(b.Bytes)
	if err != nil {
		panic(err)
	}
	return k
}

func mustParseCertificate(pemStr []byte) *x509.Certificate {
	b, _ := pem.Decode(pemStr)
	if b == nil {
		panic("cannot parse PEM")
	}
	cert, err := x509.ParseCertificate(b.Bytes)
	if err != nil {
		panic(err)
	}
	return cert
}

// idpTestOpts are options that can be applied to the identity provider.
type idpTestOpts struct {
	apply func(*testing.T, *IdentityProviderTest)
}

// applyKey will set the private key for the identity provider.
var applyKey = idpTestOpts{
	apply: func(t *testing.T, test *IdentityProviderTest) {
		test.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem"))
		(&test.IDP).Key = test.Key
	},
}

// applySigner will set the signer for the identity provider.
var applySigner = idpTestOpts{
	apply: func(t *testing.T, test *IdentityProviderTest) {
		test.Signer = mustParsePrivateKey(golden.Get(t, "idp_key.pem"))
		(&test.IDP).Signer = test.Signer
	},
}

func NewIdentityProviderTest(t *testing.T, opts ...idpTestOpts) *IdentityProviderTest {
	test := IdentityProviderTest{}
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	jwt.TimeFunc = TimeNow
	RandReader = &testRandomReader{}                // TODO(ross): remove this and use the below generator
	xmlenc.RandReader = rand.New(rand.NewSource(0)) //nolint:gosec  // deterministic random numbers for tests

	test.SPKey = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	test.SPCertificate = mustParseCertificate(golden.Get(t, "sp_cert.pem"))
	test.SP = ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}

	test.Certificate = mustParseCertificate(golden.Get(t, "idp_cert.pem"))

	test.IDP = IdentityProvider{
		Certificate: test.Certificate,
		Logger:      logger.DefaultLogger,
		MetadataURL: mustParseURL("https://idp.example.com/saml/metadata"),
		SSOURL:      mustParseURL("https://idp.example.com/saml/sso"),
		ServiceProviderProvider: &mockServiceProviderProvider{
			GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
				if serviceProviderID == test.SP.MetadataURL.String() {
					return test.SP.Metadata(), nil
				}
				return nil, os.ErrNotExist
			},
		},
		SessionProvider: &mockSessionProvider{
			GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
				return nil
			},
		},
	}

	// apply the test options
	for _, opt := range opts {
		opt.apply(t, &test)
	}

	// bind the service provider and the IDP
	test.SP.IDPMetadata = test.IDP.Metadata()
	return &test
}

type mockSessionProvider struct {
	GetSessionFunc func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session
}

func (msp *mockSessionProvider) GetSession(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
	return msp.GetSessionFunc(w, r, req)
}

type mockServiceProviderProvider struct {
	GetServiceProviderFunc func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error)
}

func (mspp *mockServiceProviderProvider) GetServiceProvider(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
	return mspp.GetServiceProviderFunc(r, serviceProviderID)
}

func TestIDPCanProduceMetadata(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	expected := &EntityDescriptor{
		ValidUntil:    TimeNow().Add(DefaultValidDuration),
		CacheDuration: DefaultValidDuration,
		EntityID:      "https://idp.example.com/saml/metadata",
		IDPSSODescriptors: []IDPSSODescriptor{
			{
				SSODescriptor: SSODescriptor{
					RoleDescriptor: RoleDescriptor{
						ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
						KeyDescriptors: []KeyDescriptor{
							{
								Use: "signing",
								KeyInfo: KeyInfo{
									XMLName: xml.Name{},
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{Data: "MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ=="},
										},
									},
								},
								EncryptionMethods: nil,
							},
							{
								Use: "encryption",
								KeyInfo: KeyInfo{
									XMLName: xml.Name{},
									X509Data: X509Data{
										X509Certificates: []X509Certificate{
											{Data: "MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ=="},
										},
									},
								},
								EncryptionMethods: []EncryptionMethod{
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes128-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes192-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#aes256-cbc"},
									{Algorithm: "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"},
								},
							},
						},
					},
					NameIDFormats: []NameIDFormat{NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient")},
				},
				SingleSignOnServices: []Endpoint{
					{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
						Location: "https://idp.example.com/saml/sso",
					},
					{
						Binding:  "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
						Location: "https://idp.example.com/saml/sso",
					},
				},
			},
		},
	}
	assert.Check(t, is.DeepEqual(expected, test.IDP.Metadata()))
}

func TestIDPHTTPCanHandleMetadataRequest(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/metadata", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml", w.Header().Get("Content-type")))
	assert.Check(t, strings.HasPrefix(w.Body.String(), "<EntityDescriptor"),
		w.Body.String())
}

func TestIDPCanHandleRequestWithNewSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			fmt.Fprintf(w, "RelayState: %s\nSAMLRequest: %s",
				req.RelayState, req.RequestBuffer)
			return nil
		},
	}

	w := httptest.NewRecorder()

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.Check(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(requestURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), "idp_authn_request.xml")
	assert.Check(t, is.Equal("ThisIsTheRelayState", requestURL.Query().Get("RelayState")))

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(200, w.Code))
	golden.Assert(t, w.Body.String(), t.Name()+"_http_response_body")
}

func TestIDPCanHandleRequestWithExistingSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.Check(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(requestURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), t.Name()+"_decodedRequest")

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(200, w.Code))
	golden.Assert(t, w.Body.String(), t.Name()+"_http_response_body")
}

func TestIDPCanHandlePostRequestWithExistingSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()

	authRequest, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
	assert.Check(t, err)
	authRequestBuf, err := xml.Marshal(authRequest)
	assert.Check(t, err)
	q := url.Values{}
	q.Set("SAMLRequest", base64.StdEncoding.EncodeToString(authRequestBuf))
	q.Set("RelayState", "ThisIsTheRelayState")

	r, _ := http.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader(q.Encode()))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")

	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(200, w.Code))
	golden.Assert(t, w.Body.String(), t.Name()+"_http_response_body")
}

func TestIDPRejectsInvalidRequest(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			panic("not reached")
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=XXX", nil)
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	w = httptest.NewRecorder()
	r, _ = http.NewRequest("POST", "https://idp.example.com/saml/sso",
		strings.NewReader("RelayState=ThisIsTheRelayState&SAMLRequest=XXX"))
	r.Header.Set("Content-type", "application/x-www-form-urlencoded")
	test.IDP.ServeSSO(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
}

func TestIDPCanParse(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D", nil)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, err)
	assert.Check(t, req.Validate())

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, is.Error(err, "cannot decompress request: unexpected EOF"))

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=NotValidBase64", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, is.Error(err, "cannot decode request: illegal base64 data at input byte 12"))

	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=bm90IGZsYXRlIGVuY29kZWQ%3D", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, is.Error(err, "cannot decompress request: flate: corrupt input before offset 1"))

	r, _ = http.NewRequest("FROBNICATE", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&SAMLRequest=lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D", nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	assert.Check(t, is.Error(err, "method not allowed"))
}

func TestIDPCanValidate(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, req.Validate())
	assert.Check(t, req.ServiceProviderMetadata != nil)
	assert.Check(t, is.DeepEqual(&IndexedEndpoint{
		Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.example.com/saml2/acs",
		Index: 1,
	}, req.ACSEndpoint))

	req = IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RequestBuffer: []byte("<AuthnRequest"),
	}
	assert.Check(t, is.Error(req.Validate(), "XML syntax error on line 1: unexpected EOF"))

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.wrongDestination.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, is.Error(req.Validate(), "expected destination to be \"https://idp.example.com/saml/sso\", not \"https://idp.wrongDestination.com/saml/sso\""))

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2014-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, is.Error(req.Validate(), "request expired at 2014-12-01 01:58:39 +0000 UTC"))

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"4.2\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, is.Error(req.Validate(), "expected SAML request version 2.0 got 4.2"))

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://unknownSP.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, is.Error(req.Validate(), "cannot handle request from unknown service provider https://unknownSP.example.com/saml2/metadata"))

	req = IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://unknown.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	assert.Check(t, is.Error(req.Validate(), "cannot find assertion consumer service: file does not exist"))

}

func TestIDPMakeAssertion(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	assert.Check(t, req.Validate())

	err := DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.Check(t, err)

	expected := &Assertion{
		ID:           "id-00020406080a0c0e10121416181a1c1e20222426",
		IssueInstant: TimeNow(),
		Version:      "2.0",
		Issuer: Issuer{
			Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
			Value:  "https://idp.example.com/saml/metadata",
		},
		Signature: nil,
		Subject: &Subject{
			NameID: &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", NameQualifier: "https://idp.example.com/saml/metadata", SPNameQualifier: "https://sp.example.com/saml2/metadata", Value: ""},
			SubjectConfirmations: []SubjectConfirmation{
				{
					Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
					SubjectConfirmationData: &SubjectConfirmationData{
						Address:      "",
						InResponseTo: "id-00020406080a0c0e10121416181a1c1e",
						NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
						Recipient:    "https://sp.example.com/saml2/acs",
					},
				},
			},
		},
		Conditions: &Conditions{
			NotBefore:    TimeNow(),
			NotOnOrAfter: TimeNow().Add(MaxIssueDelay),
			AudienceRestrictions: []AudienceRestriction{
				{
					Audience: Audience{Value: "https://sp.example.com/saml2/metadata"},
				},
			},
		},
		AuthnStatements: []AuthnStatement{
			{
				AuthnInstant:    time.Time{},
				SessionIndex:    "",
				SubjectLocality: &SubjectLocality{},
				AuthnContext: AuthnContext{
					AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"},
				},
			},
		},
		AttributeStatements: []AttributeStatement{
			{
				Attributes: []Attribute{
					{
						FriendlyName: "uid",
						Name:         "urn:oid:0.9.2342.19200300.100.1.1",
						NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
						Values: []AttributeValue{
							{
								Type:  "xs:string",
								Value: "alice",
							},
						},
					},
				},
			},
		},
	}
	assert.Check(t, is.DeepEqual(expected, req.Assertion))

	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:             "f00df00df00d",
		CreateTime:     TimeNow(),
		ExpireTime:     TimeNow().Add(time.Hour),
		Index:          "9999",
		NameID:         "ba5eba11",
		Groups:         []string{"Users", "Administrators", "♀"},
		UserName:       "alice",
		UserEmail:      "alice@example.com",
		UserCommonName: "Alice Smith",
		UserSurname:    "Smith",
		UserGivenName:  "Alice",
	})
	assert.Check(t, err)

	expectedAttributes :=
		[]Attribute{
			{
				FriendlyName: "uid",
				Name:         "urn:oid:0.9.2342.19200300.100.1.1",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice",
					},
				},
			},
			{
				FriendlyName: "eduPersonPrincipalName",
				Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice@example.com",
					},
				},
			},
			{
				FriendlyName: "sn",
				Name:         "urn:oid:2.5.4.4",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Smith",
					},
				},
			},
			{
				FriendlyName: "givenName",
				Name:         "urn:oid:2.5.4.42",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice",
					},
				},
			},
			{
				FriendlyName: "cn",
				Name:         "urn:oid:2.5.4.3",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice Smith",
					},
				},
			},
			{
				FriendlyName: "eduPersonAffiliation",
				Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Users",
					},
					{
						Type:  "xs:string",
						Value: "Administrators",
					},
					{
						Type:  "xs:string",
						Value: "♀",
					},
				},
			},
		}
	assert.Check(t, is.DeepEqual(expectedAttributes, req.Assertion.AttributeStatements[0].Attributes))
}

func TestIDPMarshalAssertion(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte("" +
			"<AuthnRequest xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"  AssertionConsumerServiceURL=\"https://sp.example.com/saml2/acs\" " +
			"  Destination=\"https://idp.example.com/saml/sso\" " +
			"  ID=\"id-00020406080a0c0e10121416181a1c1e\" " +
			"  IssueInstant=\"2015-12-01T01:57:09Z\" ProtocolBinding=\"\" " +
			"  Version=\"2.0\">" +
			"  <Issuer xmlns=\"urn:oasis:names:tc:SAML:2.0:assertion\" " +
			"    Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://sp.example.com/saml2/metadata</Issuer>" +
			"  <NameIDPolicy xmlns=\"urn:oasis:names:tc:SAML:2.0:protocol\" " +
			"    AllowCreate=\"true\">urn:oasis:names:tc:SAML:2.0:nameid-format:transient</NameIDPolicy>" +
			"</AuthnRequest>"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	assert.Check(t, err)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.Check(t, err)
	err = req.MakeAssertionEl()
	assert.Check(t, err)

	// Compare the plaintext first
	expectedPlaintext := "<saml:Assertion xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\" ID=\"id-00020406080a0c0e10121416181a1c1e20222426\" IssueInstant=\"2015-12-01T01:57:09Z\" Version=\"2.0\"><saml:Issuer Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:entity\">https://idp.example.com/saml/metadata</saml:Issuer><ds:Signature xmlns:ds=\"http://www.w3.org/2000/09/xmldsig#\"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/><ds:SignatureMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#rsa-sha1\"/><ds:Reference URI=\"#id-00020406080a0c0e10121416181a1c1e20222426\"><ds:Transforms><ds:Transform Algorithm=\"http://www.w3.org/2000/09/xmldsig#enveloped-signature\"/><ds:Transform Algorithm=\"http://www.w3.org/2001/10/xml-exc-c14n#\"/></ds:Transforms><ds:DigestMethod Algorithm=\"http://www.w3.org/2000/09/xmldsig#sha1\"/><ds:DigestValue>gjE0eLUMVt+kK0rIGYvnzHV/2Ok=</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>Jm1rrxo2x7SYTnaS97bCdnVLQGeQuCMTjiSUvwzBkWFR+xcPr+n38dXmv0q0R68tO7L2ELhLtBdLm/dWsxruN23TMGVQyHIPMgJExdnYb7fwqx6es/NAdbDUBTbSdMX0vhIlTsHu5F0bJ0Tg0iAo9uRk9VeBdkaxtPa7+4yl1PQ=</ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>MIIB7zCCAVgCCQDFzbKIp7b3MTANBgkqhkiG9w0BAQUFADA8MQswCQYDVQQGEwJVUzELMAkGA1UECAwCR0ExDDAKBgNVBAoMA2ZvbzESMBAGA1UEAwwJbG9jYWxob3N0MB4XDTEzMTAwMjAwMDg1MVoXDTE0MTAwMjAwMDg1MVowPDELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkdBMQwwCgYDVQQKDANmb28xEjAQBgNVBAMMCWxvY2FsaG9zdDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA1PMHYmhZj308kWLhZVT4vOulqx/9ibm5B86fPWwUKKQ2i12MYtz07tzukPymisTDhQaqyJ8Kqb/6JjhmeMnEOdTvSPmHO8m1ZVveJU6NoKRn/mP/BD7FW52WhbrUXLSeHVSKfWkNk6S4hk9MV9TswTvyRIKvRsw0X/gfnqkroJcCAwEAATANBgkqhkiG9w0BAQUFAAOBgQCMMlIO+GNcGekevKgkakpMdAqJfs24maGb90DvTLbRZRD7Xvn1MnVBBS9hzlXiFLYOInXACMW5gcoRFfeTQLSouMM8o57h0uKjfTmuoWHLQLi6hnF+cvCsEFiJZ4AbF+DgmO6TarJ8O05t8zvnOwJlNCASPZRH/JmF8tX0hoHuAQ==</ds:X509Certificate></ds:X509Data></ds:KeyInfo></ds:Signature><saml:Subject><saml:NameID Format=\"urn:oasis:names:tc:SAML:2.0:nameid-format:transient\" NameQualifier=\"https://idp.example.com/saml/metadata\" SPNameQualifier=\"https://sp.example.com/saml2/metadata\"/><saml:SubjectConfirmation Method=\"urn:oasis:names:tc:SAML:2.0:cm:bearer\"><saml:SubjectConfirmationData InResponseTo=\"id-00020406080a0c0e10121416181a1c1e\" NotOnOrAfter=\"2015-12-01T01:58:39Z\" Recipient=\"https://sp.example.com/saml2/acs\"/></saml:SubjectConfirmation></saml:Subject><saml:Conditions NotBefore=\"2015-12-01T01:57:09Z\" NotOnOrAfter=\"2015-12-01T01:58:39Z\"><saml:AudienceRestriction><saml:Audience>https://sp.example.com/saml2/metadata</saml:Audience></saml:AudienceRestriction></saml:Conditions><saml:AuthnStatement AuthnInstant=\"0001-01-01T00:00:00Z\"><saml:SubjectLocality/><saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport</saml:AuthnContextClassRef></saml:AuthnContext></saml:AuthnStatement><saml:AttributeStatement><saml:Attribute FriendlyName=\"uid\" Name=\"urn:oid:0.9.2342.19200300.100.1.1\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:uri\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xsi:type=\"xs:string\">alice</saml:AttributeValue></saml:Attribute></saml:AttributeStatement></saml:Assertion>"
	actualPlaintext := ""
	{
		doc := etree.NewDocument()
		doc.SetRoot(req.AssertionEl)
		el := doc.FindElement("//EncryptedAssertion/EncryptedData")
		actualPlaintextBuf, err := xmlenc.Decrypt(test.SPKey, el)
		assert.Check(t, err)
		actualPlaintext = string(actualPlaintextBuf)
	}
	assert.Check(t, is.Equal(expectedPlaintext, actualPlaintext))

	doc := etree.NewDocument()
	doc.SetRoot(req.AssertionEl)
	assertionBuffer, err := doc.WriteToBytes()
	assert.Check(t, err)
	golden.Assert(t, string(assertionBuffer), t.Name()+"_encrypted_assertion")
}

func TestIDPMakeResponsePrivateKey(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)

	testMakeResponse(t, test)
}

func TestIDPMakeResponseSigner(t *testing.T) {
	test := NewIdentityProviderTest(t, applySigner)

	testMakeResponse(t, test)
}

func testMakeResponse(t *testing.T, test *IdentityProviderTest) {
	req := IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RequestBuffer: golden.Get(t, "TestIDPMakeResponse_request_buffer"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	assert.Check(t, err)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.Check(t, err)
	err = req.MakeAssertionEl()
	assert.Check(t, err)

	req.AssertionEl = etree.NewElement("this-is-an-encrypted-assertion")
	err = req.MakeResponse()
	assert.Check(t, err)

	certificateStore := &dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{
			req.IDP.Certificate,
		},
	}
	validationCtx := dsig.NewDefaultValidationContext(certificateStore)
	validationCtx.Clock = dsig.NewFakeClockAt(req.IDP.Certificate.NotBefore)
	_, err = validationCtx.Validate(req.ResponseEl)
	assert.Check(t, err)

	response := Response{}
	err = unmarshalEtreeHack(req.ResponseEl, &response)
	assert.Check(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	doc.Indent(2)
	responseStr, err := doc.WriteToString()
	assert.Check(t, err)
	golden.Assert(t, responseStr, "TestIDPMakeResponse_response.xml")
}

func TestIDPWriteResponse(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	req := IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RelayState:    "THIS_IS_THE_RELAY_STATE",
		RequestBuffer: golden.Get(t, "TestIDPWriteResponse_RequestBuffer.xml"),
		ResponseEl:    etree.NewElement("THIS_IS_THE_SAML_RESPONSE"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err := req.Validate()
	assert.Check(t, err)

	w := httptest.NewRecorder()
	err = req.WriteResponse(w)
	assert.Check(t, err)
	assert.Check(t, is.Equal(200, w.Code))
	golden.Assert(t, w.Body.String(), t.Name()+"response.html")
}

func TestIDPIDPInitiatedNewSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			fmt.Fprintf(w, "RelayState: %s", req.RelayState)
			return nil
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
	assert.Check(t, is.Equal(200, w.Code))
	assert.Check(t, is.Equal("RelayState: ThisIsTheRelayState", w.Body.String()))
}

func TestIDPIDPInitiatedExistingSession(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "ThisIsTheRelayState")
	assert.Check(t, is.Equal(200, w.Code))
	golden.Assert(t, w.Body.String(), t.Name()+"_response")
}

func TestIDPIDPInitiatedBadServiceProvider(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{
				ID:       "f00df00df00d",
				UserName: "alice",
			}
		},
	}

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, "https://wrong.url/metadata", "ThisIsTheRelayState")
	assert.Check(t, is.Equal(http.StatusNotFound, w.Code))
}

func TestIDPCanHandleUnencryptedResponse(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(
		golden.Get(t, "TestIDPCanHandleUnencryptedResponse_idp_metadata.xml"),
		&metadata)
	assert.Check(t, err)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == "https://gitlab.example.com/users/saml/metadata" {
				return &metadata, nil
			}
			return nil, os.ErrNotExist
		},
	}

	req := IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RequestBuffer: golden.Get(t, "TestIDPCanHandleUnencryptedResponse_request"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err = req.Validate()
	assert.Check(t, err)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.Check(t, err)
	err = req.MakeAssertionEl()
	assert.Check(t, err)

	err = req.MakeResponse()
	assert.Check(t, err)

	doc := etree.NewDocument()
	doc.SetRoot(req.ResponseEl)
	doc.Indent(2)
	responseStr, _ := doc.WriteToString()
	golden.Assert(t, responseStr, t.Name()+"_response")
}

func TestIDPRequestedAttributes(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	metadata := EntityDescriptor{}
	err := xml.Unmarshal(golden.Get(t, "TestIDPRequestedAttributes_idp_metadata.xml"), &metadata)
	assert.Check(t, err)

	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.Check(t, err)

	r, _ := http.NewRequest("GET", requestURL.String(), nil)
	req, err := NewIdpAuthnRequest(&test.IDP, r)
	req.ServiceProviderMetadata = &metadata
	req.ACSEndpoint = &metadata.SPSSODescriptors[0].AssertionConsumerServices[0]
	req.SPSSODescriptor = &metadata.SPSSODescriptors[0]
	assert.Check(t, err)
	err = DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID:             "f00df00df00d",
		UserName:       "alice",
		UserEmail:      "alice@example.com",
		UserGivenName:  "Alice",
		UserSurname:    "Smith",
		UserCommonName: "Alice Smith",
	})
	assert.Check(t, err)

	expectedAttributes := []AttributeStatement{{
		Attributes: []Attribute{
			{
				FriendlyName: "Email address",
				Name:         "email",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice@example.com",
					},
				},
			},
			{
				FriendlyName: "Full name",
				Name:         "name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice Smith",
					},
				},
			},
			{
				FriendlyName: "Given name",
				Name:         "first_name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice",
					},
				},
			},
			{
				FriendlyName: "Family name",
				Name:         "last_name",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Smith",
					},
				},
			},
			{
				FriendlyName: "uid",
				Name:         "urn:oid:0.9.2342.19200300.100.1.1",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice",
					},
				},
			},
			{
				FriendlyName: "eduPersonPrincipalName",
				Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "alice@example.com",
					},
				},
			},
			{
				FriendlyName: "sn",
				Name:         "urn:oid:2.5.4.4",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Smith",
					},
				},
			},
			{
				FriendlyName: "givenName",
				Name:         "urn:oid:2.5.4.42",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice",
					},
				},
			},
			{
				FriendlyName: "cn",
				Name:         "urn:oid:2.5.4.3",
				NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
				Values: []AttributeValue{
					{
						Type:  "xs:string",
						Value: "Alice Smith",
					},
				},
			},
		}}}
	assert.Check(t, is.DeepEqual(expectedAttributes, req.Assertion.AttributeStatements))
}

func TestIDPNoDestination(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			return &Session{ID: "f00df00df00d", UserName: "alice"}
		},
	}

	metadata := EntityDescriptor{}
	err := xml.Unmarshal(golden.Get(t, "TestIDPNoDestination_idp_metadata.xml"), &metadata)
	assert.Check(t, err)
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(r *http.Request, serviceProviderID string) (*EntityDescriptor, error) {
			if serviceProviderID == "https://gitlab.example.com/users/saml/metadata" {
				return &metadata, nil
			}
			return nil, os.ErrNotExist
		},
	}

	req := IdpAuthnRequest{
		Now:           TimeNow(),
		IDP:           &test.IDP,
		RequestBuffer: golden.Get(t, "TestIDPNoDestination_request"),
	}
	req.HTTPRequest, _ = http.NewRequest("POST", "http://idp.example.com/saml/sso", nil)
	err = req.Validate()
	assert.Check(t, err)
	err = DefaultAssertionMaker{}.MakeAssertion(&req, &Session{
		ID:       "f00df00df00d",
		UserName: "alice",
	})
	assert.Check(t, err)
	err = req.MakeAssertionEl()
	assert.Check(t, err)

	err = req.MakeResponse()
	assert.Check(t, err)
}

func TestIDPRejectDecompressionBomb(t *testing.T) {
	test := NewIdentityProviderTest(t)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			fmt.Fprintf(w, "RelayState: %s\nSAMLRequest: %s",
				req.RelayState, req.RequestBuffer)
			return nil
		},
	}

	data := bytes.Repeat([]byte("a"), 768*1024*1024)
	var compressed bytes.Buffer
	w, _ := flate.NewWriter(&compressed, flate.BestCompression)
	_, err := w.Write(data)
	assert.Check(t, err)
	err = w.Close()
	assert.Check(t, err)
	encoded := base64.StdEncoding.EncodeToString(compressed.Bytes())

	r, _ := http.NewRequest("GET", "/dontcare?"+url.Values{
		"SAMLRequest": {encoded},
	}.Encode(), nil)
	_, err = NewIdpAuthnRequest(&test.IDP, r)
	assert.Error(t, err, "cannot decompress request: flate: uncompress limit exceeded (10485760 bytes)")
}

func TestIDPHTTPCanHandleSSORequest(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	w := httptest.NewRecorder()

	const validRequest = `lJJBayoxFIX%2FypC9JhnU5wszAz7lgWCLaNtFd5fMbQ1MkmnunVb%2FfUfbUqEgdhs%2BTr5zkmLW8S5s8KVD4mzvm0Cl6FIwEciRCeCRDFuznd2sTD5Upk2Ro42NyGZEmNjFMI%2BBOo9pi%2BnVWbzfrEqxY27JSEntEPfg2waHNnpJ4JtcgiWRLfoLXYBjwDfu6p%2B8JIoiWy5K4eqBUipXIzVRUwXKKtRK53qkJ3qqQVuNPUjU4TIQQ%2BBS5EqPBzofKH2ntBn%2FMervo8jWnyX%2BuVC78FwKkT1gopNKX1JUxSklXTMIfM0gsv8xeeDL%2BPGk7%2FF0Qg0GdnwQ1cW5PDLUwFDID6uquO1Dlot1bJw9%2FPLRmia%2BzRMCYyk4dSiq6205QSDXOxfy3KAq5Pkvqt4DAAD%2F%2Fw%3D%3D`

	r, _ := http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
		"SAMLRequest="+validRequest, nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))

	// rejects requests that are invalid
	w = httptest.NewRecorder()
	r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
		"SAMLRequest=PEF1dGhuUmVxdWVzdA%3D%3D", nil)
	test.IDP.Handler().ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))

	// rejects requests that contain malformed XML
	{
		a, _ := url.QueryUnescape(validRequest)
		b, _ := base64.StdEncoding.DecodeString(a)
		c, _ := io.ReadAll(flate.NewReader(bytes.NewReader(b)))
		d := bytes.Replace(c, []byte("<AuthnRequest"), []byte("<AuthnRequest ::foo=\"bar\">]]"), 1)
		f := bytes.Buffer{}
		e, _ := flate.NewWriter(&f, flate.DefaultCompression)
		_, err := e.Write(d)
		assert.Check(t, err)
		err = e.Close()
		assert.Check(t, err)
		g := base64.StdEncoding.EncodeToString(f.Bytes())
		invalidRequest := url.QueryEscape(g)

		w = httptest.NewRecorder()
		r, _ = http.NewRequest("GET", "https://idp.example.com/saml/sso?RelayState=ThisIsTheRelayState&"+
			"SAMLRequest="+invalidRequest, nil)
		test.IDP.Handler().ServeHTTP(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	}
}
