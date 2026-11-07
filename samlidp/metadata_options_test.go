package samlidp

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// fetchMetadata returns the metadata server serves at /metadata.
func fetchMetadata(t *testing.T, server *Server) *saml.EntityDescriptor {
	t.Helper()
	w := httptest.NewRecorder()
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/metadata", nil)
	server.ServeHTTP(w, r)
	assert.Assert(t, is.Equal(http.StatusOK, w.Code))
	var ed saml.EntityDescriptor
	assert.NilError(t, xml.Unmarshal(w.Body.Bytes(), &ed))
	assert.Assert(t, is.Len(ed.IDPSSODescriptors, 1))
	return &ed
}

func signingCertificates(ed *saml.EntityDescriptor) []string {
	var certs []string
	for _, kd := range ed.IDPSSODescriptors[0].KeyDescriptors {
		if kd.Use != "signing" {
			continue
		}
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			certs = append(certs, c.Data)
		}
	}
	return certs
}

// The metadata served by samlidp publishes Options.ExtraCertificates and
// Options.MetadataScopes, and its single logout endpoint with the bindings
// ServeSLO accepts.
func TestMetadataOptions(t *testing.T) {
	test := NewServerTest(t)
	scopes := []saml.ShibbolethScope{
		{Value: "example.com"},
		{Value: `^.+\.example\.com$`, Regexp: true},
	}
	server, err := New(Options{
		Certificate:       test.Certificate,
		Key:               test.Key,
		Logger:            logger.DefaultLogger,
		Store:             &MemoryStore{},
		URL:               url.URL{Scheme: "https", Host: "idp.example.com"},
		ExtraCertificates: []*x509.Certificate{test.SPCertificate},
		MetadataScopes:    scopes,
	})
	assert.NilError(t, err)

	ed := fetchMetadata(t, server)
	assert.Check(t, is.DeepEqual([]string{
		base64.StdEncoding.EncodeToString(test.Certificate.Raw),
		base64.StdEncoding.EncodeToString(test.SPCertificate.Raw),
	}, signingCertificates(ed)))

	extensions := ed.IDPSSODescriptors[0].Extensions
	assert.Assert(t, extensions != nil)
	assert.Assert(t, is.Len(extensions.ShibbolethScopes, 2))
	for i, scope := range extensions.ShibbolethScopes {
		assert.Check(t, is.Equal(scopes[i].Value, scope.Value))
		assert.Check(t, is.Equal(scopes[i].Regexp, scope.Regexp))
	}

	assert.Check(t, is.DeepEqual([]saml.Endpoint{
		{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/slo"},
		{Binding: saml.HTTPPostBinding, Location: "https://idp.example.com/slo"},
	}, ed.IDPSSODescriptors[0].SingleLogoutServices))
}

// Without the options, the metadata publishes only Certificate and no scopes,
// as before.
func TestMetadataOptionsDefault(t *testing.T) {
	test := NewServerTest(t)
	ed := fetchMetadata(t, test.Server)
	assert.Check(t, is.DeepEqual([]string{
		base64.StdEncoding.EncodeToString(test.Certificate.Raw),
	}, signingCertificates(ed)))
	assert.Check(t, is.Nil(ed.IDPSSODescriptors[0].Extensions))
}
