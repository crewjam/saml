package saml

import (
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/testsaml"
)

func TestSPAuthnRequestAcsIndex(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
	}

	// Without AcsIndex, the request names the ACS by URL and binding.
	req, err := s.MakeAuthenticationRequest("", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	assert.Check(t, is.Equal("https://15661444.ngrok.io/saml2/acs", req.AssertionConsumerServiceURL))
	assert.Check(t, is.Equal(HTTPPostBinding, req.ProtocolBinding))
	assert.Check(t, is.Equal("", req.AssertionConsumerServiceIndex))

	// With AcsIndex, it names the ACS by index only (SAML core §3.4.1).
	for _, index := range []int{0, 2, 65535} {
		s.AcsIndex = &index
		req, err = s.MakeAuthenticationRequest("", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		assert.Check(t, is.Equal("", req.AssertionConsumerServiceURL))
		assert.Check(t, is.Equal("", req.ProtocolBinding))
		assert.Check(t, is.Equal(strconv.Itoa(index), req.AssertionConsumerServiceIndex))

		doc := req.Element()
		assert.Check(t, is.Equal(strconv.Itoa(index), doc.SelectAttrValue("AssertionConsumerServiceIndex", "")))
		assert.Check(t, doc.SelectAttr("AssertionConsumerServiceURL") == nil)
		assert.Check(t, doc.SelectAttr("ProtocolBinding") == nil)
	}

	// The index is an xs:unsignedShort.
	for _, index := range []int{-1, 65536} {
		s.AcsIndex = &index
		_, err = s.MakeAuthenticationRequest("", HTTPRedirectBinding, HTTPPostBinding)
		assert.Check(t, is.ErrorContains(err, "AcsIndex"))
	}
}

// The IdP resolves the index the SP sends to the matching endpoint in the SP
// metadata, including its binding.
func TestSPToIDPAcsIndexRoundTrip(t *testing.T) {
	for _, tc := range []struct {
		index   int
		binding string
	}{
		{1, HTTPPostBinding},
		{2, HTTPArtifactBinding},
	} {
		t.Run(tc.binding, func(t *testing.T) {
			test := NewIdentityProviderTest(t, applyKey)
			index := tc.index
			test.SP.AcsIndex = &index

			requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
			assert.NilError(t, err)
			decoded, err := testsaml.ParseRedirectRequest(requestURL)
			assert.NilError(t, err)
			assert.Check(t, is.Contains(string(decoded), `AssertionConsumerServiceIndex="`+strconv.Itoa(index)+`"`))
			assert.Check(t, !strings.Contains(string(decoded), "AssertionConsumerServiceURL"))

			r := httptest.NewRequest(http.MethodGet, requestURL.String(), nil)
			req, err := NewIdpAuthnRequest(&test.IDP, r)
			assert.NilError(t, err)
			assert.NilError(t, req.Validate())
			assert.Check(t, is.Equal(index, req.ACSEndpoint.Index))
			assert.Check(t, is.Equal(tc.binding, req.ACSEndpoint.Binding))
			assert.Check(t, is.Equal(test.SP.AcsURL.String(), req.ACSEndpoint.Location))
		})
	}

	// An index the SP metadata does not have is rejected.
	test := NewIdentityProviderTest(t, applyKey)
	index := 7
	test.SP.AcsIndex = &index
	requestURL, err := test.SP.MakeRedirectAuthenticationRequest("ThisIsTheRelayState")
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, requestURL.String(), nil))
	assert.NilError(t, err)
	assert.Check(t, is.ErrorContains(req.Validate(), "cannot find assertion consumer service"))
}
