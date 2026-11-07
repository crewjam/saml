package samlidp

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/xml"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

const signedSPEntityID = "https://sp.example.com/saml2/metadata"

// signedSPMetadata returns the metadata of sp, signed with its
// key and certificate, serialized as a consumer receives it.
func signedSPMetadata(t *testing.T, sp saml.ServiceProvider) string {
	t.Helper()
	el, err := sp.SignedMetadata()
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToString()
	assert.NilError(t, err)
	return buf
}

func unsignedSPMetadata(t *testing.T, sp saml.ServiceProvider) string {
	t.Helper()
	buf, err := xml.Marshal(sp.Metadata())
	assert.NilError(t, err)
	return string(buf)
}

// putService sends metadata to PUT /services/sp and returns the status code.
func putService(t *testing.T, test *ServerTest, metadata string) int {
	t.Helper()
	// Forget the SP that NewServerTest registers, so that a successful
	// PUT is what registers it.
	delete(test.Server.serviceProviders, signedSPEntityID)

	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodPut, "https://idp.example.com/services/sp", strings.NewReader(metadata))
	test.Server.ServeHTTP(w, r)
	return w.Code
}

// assertNotRegistered checks that the SP was neither stored nor registered.
func assertNotRegistered(t *testing.T, test *ServerTest) {
	t.Helper()
	var service Service
	assert.Check(t, is.Equal(ErrNotFound, test.Store.Get("/services/sp", &service)))
	_, ok := test.Server.serviceProviders[signedSPEntityID]
	assert.Check(t, !ok)
}

// untrustedKeyAndCertificate returns a new RSA key and a self-signed
// certificate for it.
func untrustedKeyAndCertificate(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "untrusted.example.com"},
		NotBefore:    time.Date(2015, 1, 1, 0, 0, 0, 0, time.UTC),
		NotAfter:     time.Date(2035, 1, 1, 0, 0, 0, 0, time.UTC),
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

func acsLocations(md *saml.EntityDescriptor) []string {
	var rv []string
	for _, spsso := range md.SPSSODescriptors {
		for _, acs := range spsso.AssertionConsumerServices {
			rv = append(rv, acs.Location)
		}
	}
	return rv
}

func TestSPMetadataCertificatesFlowFromOptions(t *testing.T) {
	test := NewServerTest(t)
	server, err := New(Options{
		Certificate:            test.Certificate,
		Key:                    test.Key,
		Logger:                 logger.DefaultLogger,
		Store:                  &MemoryStore{},
		URL:                    url.URL{Scheme: "https", Host: "idp.example.com"},
		SPMetadataCertificates: []*x509.Certificate{test.SPCertificate},
	})
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual([]*x509.Certificate{test.SPCertificate}, server.SPMetadataCertificates))
}

func TestPutServiceWithoutSPMetadataCertificatesAcceptsUnsignedMetadata(t *testing.T) {
	test := NewServerTest(t)
	assert.Check(t, is.Len(test.Server.SPMetadataCertificates, 0))

	assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, unsignedSPMetadata(t, test.SP))))

	var service Service
	assert.NilError(t, test.Store.Get("/services/sp", &service))
	assert.Check(t, is.Equal(signedSPEntityID, service.Metadata.EntityID))
	_, ok := test.Server.serviceProviders[signedSPEntityID]
	assert.Check(t, ok)
}

func TestPutServiceWithoutSPMetadataCertificatesIgnoresSignature(t *testing.T) {
	// This is the behaviour issue #777 is about, kept when the option is
	// not set: a signature is not checked, so metadata changed after it
	// was signed is accepted.
	test := NewServerTest(t)
	metadata := strings.ReplaceAll(signedSPMetadata(t, test.SP),
		"https://sp.example.com/saml2/acs", "https://evil.example.com/acs")

	assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, metadata)))
	registered, ok := test.Server.serviceProviders[signedSPEntityID]
	assert.Assert(t, ok)
	assert.Check(t, is.Contains(acsLocations(registered), "https://evil.example.com/acs"))
}

func TestPutServiceWithSPMetadataCertificates(t *testing.T) {
	newTest := func(t *testing.T) *ServerTest {
		test := NewServerTest(t)
		test.Server.SPMetadataCertificates = []*x509.Certificate{test.SPCertificate}
		return test
	}

	t.Run("accepts validly signed metadata", func(t *testing.T) {
		test := newTest(t)
		assert.Check(t, is.Equal(http.StatusNoContent, putService(t, test, signedSPMetadata(t, test.SP))))

		var service Service
		assert.NilError(t, test.Store.Get("/services/sp", &service))
		assert.Check(t, is.Equal(signedSPEntityID, service.Metadata.EntityID))
		locations := acsLocations(&service.Metadata)
		assert.Check(t, len(locations) > 0)
		for _, location := range locations {
			assert.Check(t, is.Equal("https://sp.example.com/saml2/acs", location))
		}

		registered, ok := test.Server.serviceProviders[signedSPEntityID]
		assert.Assert(t, ok)
		assert.Check(t, is.Equal(signedSPEntityID, registered.EntityID))
	})

	t.Run("refuses tampered metadata", func(t *testing.T) {
		test := newTest(t)
		metadata := strings.ReplaceAll(signedSPMetadata(t, test.SP),
			"https://sp.example.com/saml2/acs", "https://evil.example.com/acs")
		assert.Assert(t, strings.Contains(metadata, "https://evil.example.com/acs"))

		assert.Check(t, is.Equal(http.StatusBadRequest, putService(t, test, metadata)))
		assertNotRegistered(t, test)
	})

	t.Run("refuses unsigned metadata", func(t *testing.T) {
		test := newTest(t)
		assert.Check(t, is.Equal(http.StatusBadRequest, putService(t, test, unsignedSPMetadata(t, test.SP))))
		assertNotRegistered(t, test)
	})

	t.Run("refuses metadata signed by an untrusted certificate", func(t *testing.T) {
		test := newTest(t)
		// Signed with a key and certificate of its own, which is not a
		// trusted SP metadata signing certificate. (The IdP and SP test
		// certificates share one key pair, so neither will do.)
		key, cert := untrustedKeyAndCertificate(t)
		sp := test.SP
		sp.Key = key
		sp.Certificate = cert
		assert.Check(t, is.Equal(http.StatusBadRequest, putService(t, test, signedSPMetadata(t, sp))))
		assertNotRegistered(t, test)
	})

	t.Run("refuses malformed metadata", func(t *testing.T) {
		test := newTest(t)
		assert.Check(t, is.Equal(http.StatusBadRequest, putService(t, test, "<EntityDescriptor")))
		assertNotRegistered(t, test)
	})
}
