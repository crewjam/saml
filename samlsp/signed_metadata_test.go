package samlsp

import (
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

func TestMiddlewareCanServeSignedMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)

	// Options.SignMetadata reaches the ServiceProvider; signing does not
	// need SignRequest.
	middleware, err := New(Options{
		URL:          mustParseURL("https://15661444.ngrok.io/"),
		Key:          test.Key,
		Certificate:  test.Certificate,
		IDPMetadata:  test.Middleware.ServiceProvider.IDPMetadata,
		SignMetadata: true,
	})
	assert.NilError(t, err)
	assert.Check(t, middleware.ServiceProvider.SignMetadata)

	req, _ := http.NewRequest("GET", middleware.ServiceProvider.MetadataURL.Path, nil)
	resp := httptest.NewRecorder()
	middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml", resp.Header().Get("Content-type")))

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(resp.Body.Bytes()))
	root := doc.Root()
	assert.Check(t, is.Equal("Signature", root.ChildElements()[0].Tag))

	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{test.Certificate},
	})
	validationContext.Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	_, err = validationContext.Validate(root)
	assert.NilError(t, err)

	// the signed document is still ordinary, parseable metadata
	var ed saml.EntityDescriptor
	assert.NilError(t, xml.Unmarshal(resp.Body.Bytes(), &ed))
	assert.Check(t, is.Equal(middleware.ServiceProvider.MetadataURL.String(), ed.EntityID))
	assert.Check(t, is.Len(ed.SPSSODescriptors, 1))
}

func TestMiddlewareSignedMetadataErrorIsServerError(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.Middleware.ServiceProvider.SignMetadata = true
	test.Middleware.ServiceProvider.Certificate = nil

	req, _ := http.NewRequest("GET", test.Middleware.ServiceProvider.MetadataURL.Path, nil)
	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusInternalServerError, resp.Code))
}
