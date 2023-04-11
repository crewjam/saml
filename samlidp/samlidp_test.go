package samlidp

import (
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/golang-jwt/jwt/v4"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

type testRandomReader struct {
	Next byte
}

func (tr *testRandomReader) Read(p []byte) (n int, err error) {
	for i := 0; i < len(p); i++ {
		p[i] = tr.Next
		tr.Next += 2
	}
	return len(p), nil
}

func mustParseURL(s string) url.URL {
	rv, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *rv
}

func mustParsePrivateKey(pemStr []byte) crypto.PrivateKey {
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

type ServerTest struct {
	SPKey         *rsa.PrivateKey
	SPCertificate *x509.Certificate
	SP            saml.ServiceProvider

	Key         crypto.PrivateKey
	Certificate *x509.Certificate
	Server      *Server
	Store       MemoryStore
}

func NewServerTest(t *testing.T) *ServerTest {
	test := ServerTest{}
	saml.TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	jwt.TimeFunc = saml.TimeNow
	saml.RandReader = &testRandomReader{}

	test.SPKey = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	test.SPCertificate = mustParseCertificate(golden.Get(t, "sp_cert.pem"))
	test.SP = saml.ServiceProvider{
		Key:         test.SPKey,
		Certificate: test.SPCertificate,
		MetadataURL: mustParseURL("https://sp.example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml2/acs"),
		IDPMetadata: &saml.EntityDescriptor{},
	}
	test.Key = mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "idp_cert.pem"))

	test.Store = MemoryStore{}

	var err error
	test.Server, err = New(Options{
		Certificate: test.Certificate,
		Key:         test.Key,
		Logger:      logger.DefaultLogger,
		Store:       &test.Store,
		URL:         url.URL{Scheme: "https", Host: "idp.example.com"},
	})
	if err != nil {
		panic(err)
	}

	test.SP.IDPMetadata = test.Server.IDP.Metadata()
	test.Server.serviceProviders["https://sp.example.com/saml2/metadata"] = test.SP.Metadata()
	return &test
}

func TestHTTPCanHandleMetadataRequest(t *testing.T) {
	test := NewServerTest(t)
	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", "https://idp.example.com/metadata", nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t,
		strings.HasPrefix(w.Body.String(), "<EntityDescriptor"),
		w.Body.String())
	golden.Assert(t, w.Body.String(), "http_metadata_response.html")
}

func TestHTTPCanSSORequest(t *testing.T) {
	test := NewServerTest(t)
	u, err := test.SP.MakeRedirectAuthenticationRequest("frob")
	assert.Check(t, err)

	w := httptest.NewRecorder()
	r, _ := http.NewRequest("GET", u.String(), nil)
	test.Server.ServeHTTP(w, r)
	assert.Check(t, is.Equal(http.StatusOK, w.Code))
	assert.Check(t,
		strings.HasPrefix(w.Body.String(), "<html><p></p><form method=\"post\" action=\"https://idp.example.com/sso\">"),
		w.Body.String())
	golden.Assert(t, w.Body.String(), "http_sso_response.html")
}
