//go:build !go1.17
// +build !go1.17

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
		[]byte("<EntityDescriptor "), []byte("<EntityDescriptor ::foo=\"bar\""), -1)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		w.Write(test.IDPMetadata)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, is.Error(err, "validator: in token starting at 2:1: roundtrip error: expected {{ EntityDescriptor} [{{ :foo} bar} {{ xmlns} urn:oasis:names:tc:SAML:2.0:metadata} {{xmlns ds} http://www.w3.org/2000/09/xmldsig#} {{xmlns mdalg} urn:oasis:names:tc:SAML:metadata:algsupport} {{xmlns mdui} urn:oasis:names:tc:SAML:metadata:ui} {{xmlns shibmd} urn:mace:shibboleth:metadata:1.0} {{xmlns xsi} http://www.w3.org/2001/XMLSchema-instance} {{ Name} urn:mace:shibboleth:testshib:two} {{ entityID} https://idp.testshib.org/idp/shibboleth}]}, observed {{ EntityDescriptor} [{{ foo} bar} {{ xmlns} urn:oasis:names:tc:SAML:2.0:metadata} {{xmlns ds} http://www.w3.org/2000/09/xmldsig#} {{xmlns mdalg} urn:oasis:names:tc:SAML:metadata:algsupport} {{xmlns mdui} urn:oasis:names:tc:SAML:metadata:ui} {{xmlns shibmd} urn:mace:shibboleth:metadata:1.0} {{xmlns xsi} http://www.w3.org/2001/XMLSchema-instance} {{ Name} urn:mace:shibboleth:testshib:two} {{ entityID} https://idp.testshib.org/idp/shibboleth} {{ entityID} https://idp.testshib.org/idp/shibboleth}]}"))
	assert.Check(t, is.Nil(md))
}
