package samlsp

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Tests in this file pin behavior required by the OASIS SAML V2.0 Metadata
// specification (saml-metadata-2.0-os).

// saml-metadata-2.0-os §4.3.2 (lines 1407-1409): "Publishers MAY issue an
// HTTP Redirect (301 Moved Permanently, 302 or 307 Temporary Redirect)
// [RFC2616], and user agents MUST follow the specified URL in the Redirect
// response." FetchMetadata follows each of them.
func TestSpecMetadata_4_3_2_FetchMetadataFollowsRedirects(t *testing.T) {
	test := NewMiddlewareTest(t)
	for _, status := range []int{http.StatusMovedPermanently, http.StatusFound, http.StatusTemporaryRedirect} {
		testServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/old":
				http.Redirect(w, r, "/new", status)
			case "/new":
				_, err := w.Write(test.IDPMetadata)
				assert.Check(t, err)
			default:
				http.NotFound(w, r)
			}
		}))
		u, _ := url.Parse(testServer.URL + "/old")
		md, err := FetchMetadata(context.Background(), testServer.Client(), *u)
		assert.Check(t, err, "status %d", status)
		if md != nil {
			assert.Check(t, is.Equal("https://idp.testshib.org/idp/shibboleth", md.EntityID), "status %d", status)
		}

		md, err = FetchMetadataByEntityID(context.Background(), testServer.Client(), *u, "https://idp.testshib.org/idp/shibboleth")
		assert.Check(t, err, "status %d", status)
		assert.Check(t, md != nil, "status %d", status)
		testServer.Close()
	}
}

// saml-metadata-2.0-os §2.3 (lines 307-309): a metadata instance has either
// an <EntityDescriptor> or an <EntitiesDescriptor> root. ParseMetadata
// accepts both, and keeps the validUntil and cacheDuration of an
// EntityDescriptor root (§2.3.2 lines 376-381) for the caller.
func TestSpecMetadata_2_3_ParseMetadataRootElements(t *testing.T) {
	const idp = `<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://idp.example.org/idp"%s>` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` +
		`<SingleSignOnService Binding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect" Location="https://idp.example.org/sso"/>` +
		`</IDPSSODescriptor></EntityDescriptor>`

	single := strings.Replace(idp, "%s", ` validUntil="2030-01-02T03:04:05Z" cacheDuration="PT6H"`, 1)
	md, err := ParseMetadata([]byte(single))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://idp.example.org/idp", md.EntityID))
	assert.Check(t, md.ValidUntil.Equal(time.Date(2030, time.January, 2, 3, 4, 5, 0, time.UTC)))
	assert.Check(t, is.Equal(6*time.Hour, md.CacheDuration))

	aggregate := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" cacheDuration="PT1H">` +
		strings.Replace(idp, "%s", "", 1) + `</EntitiesDescriptor>`
	md, err = ParseMetadata([]byte(aggregate))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://idp.example.org/idp", md.EntityID))
	assert.Check(t, is.Len(md.IDPSSODescriptors, 1))
}

// saml-metadata-2.0-os §2.3.2 (lines 406-407): the root EntityDescriptor of a
// metadata instance MUST contain either a validUntil or a cacheDuration
// attribute; §4.1.1 (lines 1234-1238): published metadata has an
// EntityDescriptor root whose entityID is the publication URL, served as
// application/samlmetadata+xml. The middleware's SP metadata meets both.
func TestSpecMetadata_2_3_2_MiddlewareMetadataRoot(t *testing.T) {
	test := NewMiddlewareTest(t)
	req, _ := http.NewRequest("GET", test.Middleware.ServiceProvider.MetadataURL.Path, nil)
	resp := httptest.NewRecorder()
	test.Middleware.ServeHTTP(resp, req)
	assert.Check(t, is.Equal(http.StatusOK, resp.Code))
	assert.Check(t, is.Equal("application/samlmetadata+xml", resp.Header().Get("Content-Type")))

	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(resp.Body.Bytes()))
	root := doc.Root()
	assert.Check(t, is.Equal("EntityDescriptor", root.Tag))
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:metadata", root.NamespaceURI()))
	assert.Check(t, root.SelectAttr("validUntil") != nil || root.SelectAttr("cacheDuration") != nil)
	assert.Check(t, is.Equal(test.Middleware.ServiceProvider.MetadataURL.String(), root.SelectAttrValue("entityID", "")))
}
