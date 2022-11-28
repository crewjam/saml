//go:build go1.17
// +build go1.17

package saml

import (
	"encoding/base64"
	"encoding/xml"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"
)

func TestSPRejectsMalformedResponse(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from google
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := golden.Get(t, "TestSPRejectsMalformedResponse_response")
	test.IDPMetadata = golden.Get(t, "TestSPRejectsMalformedResponse_IDPMetadata")

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	// this is a valid response
	{
		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", string(SamlResponse))
		assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
		assert.Check(t, err)
		assert.Check(t, is.Equal("ross@octolabs.io", assertion.Subject.NameID.Value))
	}

	// this is a valid response but with a comment injected
	{
		x, _ := base64.StdEncoding.DecodeString(string(SamlResponse))
		y := strings.Replace(string(x), "<saml2p:Response", "<saml2p:Response ::foo=\"bar\"", 1)
		SamlResponse = []byte(base64.StdEncoding.EncodeToString([]byte(y)))

		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", string(SamlResponse))
		assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
		assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
			"cannot validate signature on Response: Signature could not be verified"))
		assert.Check(t, is.Nil(assertion))
	}
}

func TestSPInvalidResponses(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", "???")
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot parse base64: illegal base64 data at input byte 0"))

	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString([]byte("<hello>World!</hello>")))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot unmarshal response: expected element type <Response> but have <hello>"))

	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"wrongRequestID"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`InResponseTo` does not match any of the possible request IDs (expected [wrongRequestID])"))

	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Nov 30 20:57:09 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"response IssueInstant expired at 2015-12-01 01:57:51.375 +0000 UTC"))
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s.IDPMetadata.EntityID = "http://snakeoil.com"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"response Issuer does not match the IDP metadata (expected \"http://snakeoil.com\")"))
	s.IDPMetadata.EntityID = "https://idp.testshib.org/idp/shibboleth"

	oldSpStatusSuccess := StatusSuccess
	StatusSuccess = "not:the:success:value"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"urn:oasis:names:tc:SAML:2.0:status:Success"))
	StatusSuccess = oldSpStatusSuccess

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data = "invalid"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Assertion: cannot parse certificate: illegal base64 data at input byte 4"))

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data = "aW52YWxpZA=="
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})

	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Assertion: x509: malformed certificate"))
}
