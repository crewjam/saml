package samlsp

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestFetchMetadata(t *testing.T) {
	test := NewMiddlewareTest(t)

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		_, err := w.Write(test.IDPMetadata)
		assert.Check(t, err)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, err)
	assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", md.EntityID))
}

func TestFetchMetadataRejectsInvalid(t *testing.T) {
	test := NewMiddlewareTest(t)
	test.IDPMetadata = bytes.ReplaceAll(test.IDPMetadata,
		[]byte("<EntityDescriptor "), []byte("<EntityDescriptor ::foo=\"bar\">]]"))

	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		assert.Check(t, is.Equal("/metadata", r.URL.String()))
		_, err := w.Write(test.IDPMetadata)
		assert.Check(t, err)
	}))

	fmt.Println(testServer.URL + "/metadata")
	u, _ := url.Parse(testServer.URL + "/metadata")
	md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
	assert.Check(t, err != nil)
	assert.Check(t, is.Nil(md))
}

const testAggregateMetadata = `<?xml version="1.0" encoding="UTF-8"?>
<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" Name="urn:example:federation">
  <EntityDescriptor entityID="https://sp.example.org/shibboleth">
    <SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <AssertionConsumerService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" Location="https://sp.example.org/acs" index="0"/>
    </SPSSODescriptor>
  </EntityDescriptor>
  <EntityDescriptor entityID="https://idp1.example.org/idp">
    <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
      <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp1.example.org/sso"/>
    </IDPSSODescriptor>
  </EntityDescriptor>
  <EntitiesDescriptor Name="urn:example:federation:members">
    <EntitiesDescriptor Name="urn:example:federation:members:universities">
      <EntityDescriptor entityID="https://idp2.example.org/idp">
        <IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">
          <SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp2.example.org/sso"/>
        </IDPSSODescriptor>
      </EntityDescriptor>
    </EntitiesDescriptor>
  </EntitiesDescriptor>
</EntitiesDescriptor>`

func TestParseMetadataByEntityID(t *testing.T) {
	t.Run("aggregate, not the first IDP", func(t *testing.T) {
		// ParseMetadata can only return the first IDP in an aggregate
		md, err := ParseMetadata([]byte(testAggregateMetadata))
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp1.example.org/idp", md.EntityID))

		md, err = ParseMetadataByEntityID([]byte(testAggregateMetadata), "https://idp2.example.org/idp")
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp2.example.org/idp", md.EntityID))
		assert.Assert(t, is.Len(md.IDPSSODescriptors, 1))
		assert.Check(t, is.Equal("https://idp2.example.org/sso", md.IDPSSODescriptors[0].SingleSignOnServices[0].Location))
	})

	t.Run("aggregate, top level", func(t *testing.T) {
		md, err := ParseMetadataByEntityID([]byte(testAggregateMetadata), "https://idp1.example.org/idp")
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp1.example.org/sso", md.IDPSSODescriptors[0].SingleSignOnServices[0].Location))
	})

	t.Run("aggregate, not found", func(t *testing.T) {
		md, err := ParseMetadataByEntityID([]byte(testAggregateMetadata), "https://idp3.example.org/idp")
		assert.Check(t, is.Error(err, `no entity found with entityID "https://idp3.example.org/idp"`))
		assert.Check(t, is.Nil(md))
	})

	t.Run("single entity", func(t *testing.T) {
		test := NewMiddlewareTest(t)
		md, err := ParseMetadataByEntityID(test.IDPMetadata, "https://idp.testshib.org/idp/shibboleth")
		assert.Assert(t, err)
		assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", md.EntityID))

		md, err = ParseMetadataByEntityID(test.IDPMetadata, "https://idp2.example.org/idp")
		assert.Check(t, is.Error(err, `no entity found with entityID "https://idp2.example.org/idp"`))
		assert.Check(t, is.Nil(md))
	})

	t.Run("rejects invalid", func(t *testing.T) {
		data := strings.Replace(testAggregateMetadata,
			`<EntityDescriptor entityID="https://idp2.example.org/idp">`,
			`<EntityDescriptor ::foo="bar" entityID="https://idp2.example.org/idp">]]`, 1)
		md, err := ParseMetadataByEntityID([]byte(data), "https://idp2.example.org/idp")
		assert.Check(t, err != nil)
		assert.Check(t, is.Nil(md))
	})

	t.Run("empty", func(t *testing.T) {
		md, err := ParseMetadataByEntityID(nil, "https://idp2.example.org/idp")
		assert.Check(t, err != nil)
		assert.Check(t, is.Nil(md))
	})
}

func TestFetchMetadataByEntityID(t *testing.T) {
	testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/metadata" {
			http.NotFound(w, r)
			return
		}
		_, err := w.Write([]byte(testAggregateMetadata))
		assert.Check(t, err)
	}))
	defer testServer.Close()

	md, err := FetchMetadataByEntityID(context.Background(), testServer.Client(),
		mustParseURL(testServer.URL+"/metadata"), "https://idp2.example.org/idp")
	assert.Assert(t, err)
	assert.Check(t, is.Equal("https://idp2.example.org/idp", md.EntityID))

	_, err = FetchMetadataByEntityID(context.Background(), testServer.Client(),
		mustParseURL(testServer.URL+"/missing"), "https://idp2.example.org/idp")
	assert.Check(t, is.Error(err, "failed to fetch metadata: unexpected status code 404"))
}
