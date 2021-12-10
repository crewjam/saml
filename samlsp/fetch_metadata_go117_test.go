//go:build go1.17
// +build go1.17

package samlsp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestFetchMetadataRejectsInvalid(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.IDPMetadata = bytes.Replace(test.IDPMetadata,
		[]byte("<EntityDescriptor "), []byte("<EntityDescriptor ::foo=\"bar\">]]"), -1)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		w.Write(test.IDPMetadata)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, is.Error(err, "expected element <EntityDescriptor> in name space urn:oasis:names:tc:SAML:2.0:metadata but have no name space"))
	assert.Check(t, is.Nil(md))
}
