package saml

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"

	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
	"gotest.tools/golden"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/JBake/saml/testsaml"
)

type ServiceProviderTest struct {
	AuthnRequest []byte
	SamlResponse []byte
	Key          *rsa.PrivateKey
	Certificate  *x509.Certificate
	IDPMetadata  []byte
}

// Helper to decode SAML redirect binding requests
// http://play.golang.org/p/sTlV0pCS2y
//     x1 := "lJJBj9MwEIX%2FSuR7Y4%2FJRisriVS2Qqq0QNUAB27GmbYWiV08E6D%2FHqeA6AnKdfz85nvPbtYzn8Iev8xIXHyfxkCtmFMw0ZInE%2ByEZNiZfv362ehSmXOKHF0cRbEmwsQ%2BhqcYaJ4w9Zi%2Beofv98%2BtODGfyUgJD3UNVVWV4Zji59JHSXYatbSORLHJO32wi8efG344l5wP6OQ%2FlTEdl4HMWw9%2BRLlgaLnHwSd0LPv%2BrSi2m1b4YaWU0qpStXpUVjmFoEBDBTU8ggUHmIVEM24DsQ3cCq3gYQV6peCdAvMCjIaPotj9ivfSh8GHYytE8QETXQlzfNE1V5d0T1X2d0GieBXTZPnv8mWScxyuUoOBPV9E968iJ2Q7WLaN%2FAnWNW%2Byz3azi6N3l%2F980XGM354SWsZWcJpRdPcDc7KBfMZu5C1B18jbL9b9CAAA%2F%2F8%3D"
//     x2, _ := url.QueryUnescape(x1)
//     x3, _ := base64.StdEncoding.DecodeString(x2)
//     x4, _ := ioutil.ReadAll(flate.NewReader(bytes.NewReader(x3)))
//     fmt.Printf("%s\n", x4)

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

func NewServiceProviderTest(t *testing.T) *ServiceProviderTest {
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Mon Dec 1 01:57:09 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	RandReader = &testRandomReader{}

	test := ServiceProviderTest{}
	test.AuthnRequest = golden.Get(t, "SP_AuthnRequest")
	test.SamlResponse = golden.Get(t, "SP_SamlResponse")
	test.Key = mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey)
	test.Certificate = mustParseCertificate(golden.Get(t, "sp_cert.pem"))
	test.IDPMetadata = golden.Get(t, "SP_IDPMetadata")
	return &test
}

func TestSPCanSetAuthenticationNameIDFormat(t *testing.T) {
	test := NewServiceProviderTest(t)

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
	}

	// defaults to "transient"
	req, err := s.MakeAuthenticationRequest("", HTTPRedirectBinding)
	assert.Check(t, err)
	assert.Check(t, is.Equal(string(TransientNameIDFormat), *req.NameIDPolicy.Format))

	// explicitly set to "transient"
	s.AuthnNameIDFormat = TransientNameIDFormat
	req, err = s.MakeAuthenticationRequest("", HTTPRedirectBinding)
	assert.Check(t, err)
	assert.Check(t, is.Equal(string(TransientNameIDFormat), *req.NameIDPolicy.Format))

	// explicitly set to "unspecified"
	s.AuthnNameIDFormat = UnspecifiedNameIDFormat
	req, err = s.MakeAuthenticationRequest("", HTTPRedirectBinding)
	assert.Check(t, err)
	assert.Check(t, is.Equal("", *req.NameIDPolicy.Format))

	// explicitly set to "emailAddress"
	s.AuthnNameIDFormat = EmailAddressNameIDFormat
	req, err = s.MakeAuthenticationRequest("", HTTPRedirectBinding)
	assert.Check(t, err)
	assert.Check(t, is.Equal(string(EmailAddressNameIDFormat), *req.NameIDPolicy.Format))
}

func TestSPCanProduceMetadataWithEncryptionCert(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		SloURL:      mustParseURL("https://example.com/saml2/slo"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(spMetadata), t.Name()+"_metadata")
}

func TestSPCanProduceMetadataWithBothCerts(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:          mustParseURL("https://example.com/saml2/acs"),
		SloURL:          mustParseURL("https://example.com/saml2/slo"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: "not-empty",
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(spMetadata), t.Name()+"_metadata")

}

func TestCanProduceMetadataNoCerts(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(spMetadata), t.Name()+"_metadata")
}

func TestCanProduceMetadataEntityID(t *testing.T) {
	test := NewServiceProviderTest(t)
	s := ServiceProvider{
		EntityID:    "spn:11111111-2222-3333-4444-555555555555",
		MetadataURL: mustParseURL("https://example.com/saml2/metadata"),
		AcsURL:      mustParseURL("https://example.com/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	spMetadata, err := xml.MarshalIndent(s.Metadata(), "", "  ")
	assert.Check(t, err)
	golden.Assert(t, string(spMetadata), t.Name()+"_metadata")
}

func TestSPCanProduceRedirectRequest(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
	assert.Check(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	assert.Check(t, is.Equal("idp.testshib.org",
		redirectURL.Host))
	assert.Check(t, is.Equal("/idp/profile/SAML2/Redirect/SSO",
		redirectURL.Path))
	golden.Assert(t, string(decodedRequest), t.Name()+"_decoded_request")
}

func TestSPCanProducePostRequest(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2015")
		return rv
	}
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	form, err := s.MakePostAuthenticationRequest("relayState")
	assert.Check(t, err)
	golden.Assert(t, string(form), t.Name()+"_form")
}

func TestSPCanProduceSignedRequestRedirectBinding(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: dsig.RSASHA1SignatureMethod,
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	redirectURL, err := s.MakeRedirectAuthenticationRequest("relayState")
	assert.Check(t, err)
	// Signature we check against in the query string was validated with
	// https://www.samltool.com/validate_authn_req.php . Once we add
	// support for validating signed AuthN requests in the IDP implementation
	// we can switch to testing using that.
	golden.Assert(t, redirectURL.RawQuery, t.Name()+"_queryString")

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	assert.Check(t, is.Equal("idp.testshib.org",
		redirectURL.Host))
	assert.Check(t, is.Equal("/idp/profile/SAML2/Redirect/SSO",
		redirectURL.Path))
	// Contains no enveloped signature
	golden.Assert(t, string(decodedRequest), t.Name()+"_decodedRequest")
}

func TestSPCanProduceSignedRequestPostBinding(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: dsig.RSASHA1SignatureMethod,
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	htmlForm, err := s.MakePostAuthenticationRequest("relayState")
	assert.Check(t, err)
	rgx := regexp.MustCompile(`\"SAMLRequest\" value=\"(.*?)\" /><input`)
	rs := rgx.FindStringSubmatch(string(htmlForm))
	assert.Check(t, len(rs) == 2)

	decodedRequest, err := base64.StdEncoding.DecodeString(html.UnescapeString(rs[1]))
	assert.Check(t, err)
	golden.Assert(t, string(decodedRequest), t.Name()+"_decodedRequest")
}

func TestSPFailToProduceSignedRequestWithBogusSignatureMethod(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:             test.Key,
		Certificate:     test.Certificate,
		MetadataURL:     mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:          mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata:     &EntityDescriptor{},
		SignatureMethod: "bogus",
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	_, err = s.MakeRedirectAuthenticationRequest("relayState")
	assert.Check(t, is.ErrorContains(err, ""), "invalid signing method bogus")
}

func TestSPCanProducePostLogoutRequest(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2015")
		return rv
	}
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	form, err := s.MakePostLogoutRequest("ros@octolabs.io", "relayState")
	assert.Check(t, err)
	golden.Assert(t, string(form), t.Name()+"_form")
}

func TestSPCanProduceRedirectLogoutRequest(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	redirectURL, err := s.MakeRedirectLogoutRequest("ross@octolabs.io", "relayState")
	assert.Check(t, err)

	decodedRequest, err := testsaml.ParseRedirectRequest(redirectURL)
	assert.Check(t, err)
	assert.Check(t, is.Equal("idp.testshib.org",
		redirectURL.Host))
	assert.Check(t, is.Equal("/idp/profile/SAML2/Redirect/SLO",
		redirectURL.Path))
	golden.Assert(t, string(decodedRequest), t.Name()+"_decodedRequest")
}

func TestSPCanProducePostLogoutResponse(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Mon Dec 1 01:31:21 UTC 2015")
		return rv
	}
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	form, err := s.MakePostLogoutResponse("id-d40c15c104b52691eccf0a2a5c8a15595be75423", "relayState")
	assert.Check(t, err)
	golden.Assert(t, string(form), t.Name()+"_form")
}

func TestSPCanProduceRedirectLogoutResponse(t *testing.T) {
	test := NewServiceProviderTest(t)
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05.999999999 UTC 2006", "Mon Dec 1 01:31:21.123456789 UTC 2015")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	redirectURL, err := s.MakeRedirectLogoutResponse("id-d40c15c104b52691eccf0a2a5c8a15595be75423", "relayState")
	assert.Check(t, err)

	decodedResponse, err := testsaml.ParseRedirectResponse(redirectURL)
	assert.Check(t, err)
	golden.Assert(t, string(decodedResponse), t.Name()+"_decodedResponse")
}

func TestSPCanHandleOneloginResponse(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from onelogin
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	SamlResponse := golden.Get(t, "TestSPCanHandleOneloginResponse_response")
	test.IDPMetadata = golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata")

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-d40c15c104b52691eccf0a2a5c8a15595be75423"})
	assert.Check(t, err)

	assert.Check(t, is.Equal("ross@kndr.org", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:       "User.email",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "ross@kndr.org",
				},
			},
		},
		{
			Name:       "memberOf",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "",
				},
			},
		},
		{
			Name:       "User.LastName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Kinder",
				},
			},
		},
		{
			Name:       "PersonImmutableID",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "",
				},
			},
		},
		{
			Name:       "User.FirstName",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Ross",
				},
			},
		},
	},
		assertion.AttributeStatements[0].Attributes))
}

func TestSPCanHandleOktaSignedResponseEncryptedAssertion(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:24:28 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := golden.Get(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_response")
	test.IDPMetadata = golden.Get(t, "TestSPCanHandleOktaSignedResponseEncryptedAssertion_IDPMetadata")
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-a7364d1e4432aa9085a7a8bd824ea2fa8fa8f684"})
	assert.Check(t, err)

	assert.Check(t, is.Equal("testuser@testrsc.com", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func TestSPCanHandleOktaResponseEncryptedSignedAssertion(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:31:55 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := golden.Get(t, "TestSPCanHandleOktaResponseEncryptedSignedAssertion_response")
	test.IDPMetadata = golden.Get(t, "TestSPCanHandleOktaResponseEncryptedSignedAssertion_IDPMetadata")

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-6d976cdde8e76df5df0a8ff58148fc0b7ec6796d"})
	assert.Check(t, err)

	assert.Check(t, is.Equal("testuser@testrsc.com", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func TestSPCanHandleOktaResponseEncryptedAssertionBothSigned(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from okta - captured with trivial.go + test.Key/test.Certificate
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Mar 3 19:40:54 UTC 2020")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := golden.Get(t, "TestSPCanHandleOktaResponseEncryptedAssertionBothSigned_response")
	test.IDPMetadata = golden.Get(t, "TestSPCanHandleOktaResponseEncryptedAssertionBothSigned_IDPMetadata")

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://localhost:8000/saml/metadata"),
		AcsURL:      mustParseURL("http://localhost:8000/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-953d4cab69ff475c5901d12e585b0bb15a7b85fe"})
	assert.Check(t, err)

	assert.Check(t, is.Equal("testuser@testrsc.com", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:       "Username",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:unspecified",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "FixedValue",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func TestSPCanHandlePlaintextResponse(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from google
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	SamlResponse := golden.Get(t, "TestSPCanHandlePlaintextResponse_response")
	test.IDPMetadata = golden.Get(t, "TestSPCanHandlePlaintextResponse_IDPMetadata")

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
	assert.Check(t, err)

	assert.Check(t, is.Equal("ross@octolabs.io", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:   "phone",
			Values: nil,
		},
		{
			Name:   "address",
			Values: nil,
		},
		{
			Name:   "jobTitle",
			Values: nil,
		},
		{
			Name: "firstName",
			Values: []AttributeValue{
				{
					Type:  "xs:anyType",
					Value: "Ross",
				},
			},
		},
		{
			Name: "lastName",
			Values: []AttributeValue{
				{
					Type:  "xs:anyType",
					Value: "Kinder",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func TestSPRejectsInjectedComment(t *testing.T) {
	test := NewServiceProviderTest(t)
	// An actual response from google
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 16:55:39 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	SamlResponse := golden.Get(t, "TestSPRejectsInjectedComment_response")
	test.IDPMetadata = golden.Get(t, "TestSPRejectsInjectedComment_IDPMetadata")

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
		y := strings.Replace(string(x), "ross@octolabs.io", "ross@<!-- and a comment -->octolabs.io", 1)
		SamlResponse = []byte(base64.StdEncoding.EncodeToString([]byte(y)))

		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", string(SamlResponse))
		assertion, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})

		// Note: I would expect the injected comment to be stripped and for the signature
		// to validate. Less ideal, but not insecure is the case where the comment breaks
		// the signature, perhaps because xml-c18n isn't being implemented correctly by
		// dsig.
		if err == nil {
			assert.Check(t, is.Equal("ross@octolabs.io",
				assertion.Subject.NameID.Value))
		}
	}

	// this is an invalid response with a commend injected per CVE-2018-7340
	// ref: https://duo.com/blog/duo-finds-saml-vulnerabilities-affecting-multiple-implementations
	// it *MUST NOT* validate
	{
		x, _ := base64.StdEncoding.DecodeString(string(SamlResponse))
		y := strings.Replace(string(x), "ross@octolabs.io", "ross@octolabs.io<!-- and a comment -->.example.com", 1)
		SamlResponse = []byte(base64.StdEncoding.EncodeToString([]byte(y)))

		req := http.Request{PostForm: url.Values{}}
		req.PostForm.Set("SAMLResponse", string(SamlResponse))
		_, err := s.ParseResponse(&req, []string{"id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6"})
		assert.Check(t, err != nil)

		realErr := err.(*InvalidResponseError).PrivateErr
		assert.Check(t, is.Error(realErr,
			"cannot validate signature on Response: Signature could not be verified"))
	}
}

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
			"invalid xml: validator: in token starting at 1:55: roundtrip error: expected {{saml2p Response} [{{ :foo} bar} {{xmlns saml2p} urn:oasis:names:tc:SAML:2.0:protocol} {{ Destination} https://29ee6d2e.ngrok.io/saml/acs} {{ ID} _fc141db284eb3098605351bde4d9be59} {{ InResponseTo} id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6} {{ IssueInstant} 2016-01-05T16:55:39.348Z} {{ Version} 2.0}]}, observed {{ Response} [{{ xmlns} saml2p} {{ foo} bar} {{xmlns saml2p} urn:oasis:names:tc:SAML:2.0:protocol} {{ Destination} https://29ee6d2e.ngrok.io/saml/acs} {{ ID} _fc141db284eb3098605351bde4d9be59} {{ InResponseTo} id-fd419a5ab0472645427f8e07d87a3a5dd0b2e9a6} {{ IssueInstant} 2016-01-05T16:55:39.348Z} {{ Version} 2.0} {{ Version} 2.0}]}"))
		assert.Check(t, is.Nil(assertion))
	}
}

func TestSPCanParseResponse(t *testing.T) {
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
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, err)

	assert.Check(t, is.DeepEqual([]Attribute{
		{
			FriendlyName: "uid",
			Name:         "urn:oid:0.9.2342.19200300.100.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "myself",
				},
			},
		},
		{
			FriendlyName: "eduPersonAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.1",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Member",
				},
				{
					Type:  "xs:string",
					Value: "Staff",
				},
			},
		},
		{
			FriendlyName: "eduPersonPrincipalName",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.6",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "myself@testshib.org",
				},
			},
		},
		{
			FriendlyName: "sn",
			Name:         "urn:oid:2.5.4.4",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "And I",
				},
			},
		},
		{
			FriendlyName: "eduPersonScopedAffiliation",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.9",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Member@testshib.org",
				},
				{
					Type:  "xs:string",
					Value: "Staff@testshib.org",
				},
			},
		},
		{
			FriendlyName: "givenName",
			Name:         "urn:oid:2.5.4.42",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Me Myself",
				},
			},
		},
		{
			FriendlyName: "eduPersonEntitlement",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.7",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "urn:mace:dir:entitlement:common-lib-terms",
				},
			},
		},
		{
			FriendlyName: "cn",
			Name:         "urn:oid:2.5.4.3",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "Me Myself And I",
				},
			},
		},
		{
			FriendlyName: "eduPersonTargetedID",
			Name:         "urn:oid:1.3.6.1.4.1.5923.1.1.1.10",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					NameID: &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", NameQualifier: "https://idp.testshib.org/idp/shibboleth", SPNameQualifier: "https://15661444.ngrok.io/saml2/metadata", Value: "8F+M9ovyaYNwCId0pVkVsnZYRDo="},
				},
			},
		},
		{
			FriendlyName: "telephoneNumber",
			Name:         "urn:oid:2.5.4.20",
			NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:uri",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "555-5555",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func (test *ServiceProviderTest) replaceDestination(newDestination string) {
	newStr := ""
	if newDestination != "" {
		newStr = `Destination="` + newDestination + `"`
	}
	test.SamlResponse = bytes.Replace(test.SamlResponse,
		[]byte(`Destination="https://15661444.ngrok.io/saml2/acs"`), []byte(newStr), 1)
}

func TestSPCanProcessResponseWithoutDestination(t *testing.T) {
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
	test.replaceDestination("")
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, err)
}

func (test *ServiceProviderTest) responseDom() (doc *etree.Document) {
	doc = etree.NewDocument()
	doc.ReadFromBytes(test.SamlResponse)
	return doc
}

func addSignatureToDocument(doc *etree.Document) *etree.Document {
	responseEl := doc.FindElement("//Response")
	signatureEl := doc.CreateElement("xmldsig:Signature")
	signatureEl.CreateAttr("xmlns:xmldsig", "http://www.w3.org/2000/09/xmldsig#")
	responseEl.AddChild(signatureEl)
	return doc
}

func removeDestinationFromDocument(doc *etree.Document) *etree.Document {
	responseEl := doc.FindElement("//Response")
	responseEl.RemoveAttr("Destination")
	return doc
}

func TestServiceProviderMismatchedDestinationsWithSignaturePresent(t *testing.T) {
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
	s.AcsURL = mustParseURL("https://wrong/saml2/acs")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://wrong/saml2/acs\", actual \"https://15661444.ngrok.io/saml2/acs\")"))
}

func TestServiceProviderMissingDestinationWithSignaturePresent(t *testing.T) {
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
	bytes, _ := removeDestinationFromDocument(addSignatureToDocument(test.responseDom())).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"\")"))
}

func TestSPMismatchedDestinationsWithSignaturePresent(t *testing.T) {
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
	test.replaceDestination("https://wrong/saml2/acs")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"https://wrong/saml2/acs\")"))
}

func TestSPMismatchedDestinationsWithNoSignaturePresent(t *testing.T) {
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
	test.replaceDestination("https://wrong/saml2/acs")
	bytes, _ := test.responseDom().WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"https://wrong/saml2/acs\")"))
}

func TestSPMissingDestinationWithSignaturePresent(t *testing.T) {
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
	test.replaceDestination("")
	bytes, _ := addSignatureToDocument(test.responseDom()).WriteToBytes()
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(bytes))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"`Destination` does not match AcsURL (expected \"https://15661444.ngrok.io/saml2/acs\", actual \"\")"))
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

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "invalid"
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: cannot parse certificate: illegal base64 data at input byte 4"))

	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "aW52YWxpZA=="
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})

	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: asn1: structure error: tags don't match (16 vs {class:1 tag:9 length:110 isCompound:true}) {optional:false explicit:false application:false private:false defaultValue:<nil> tag:<nil> stringType:0 timeType:0 set:false omitEmpty:false} certificate @2"))
}

func TestSPInvalidAssertions(t *testing.T) {
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
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(test.SamlResponse))
	s.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.Certificate = "invalid"
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assertionBuf := []byte(err.(*InvalidResponseError).Response)

	assertion := Assertion{}
	err = xml.Unmarshal(assertionBuf, &assertion)
	assert.Check(t, err)

	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow().Add(time.Hour))
	assert.Check(t, is.Error(err, "expired on 2015-12-01 01:57:51.375 +0000 UTC"))

	assertion.Issuer.Value = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "issuer is not \"https://idp.testshib.org/idp/shibboleth\""))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.NameID.NameQualifier = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, err) // not verified
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.NameID.SPNameQualifier = "bob"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, err) // not verified
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	err = s.validateAssertion(&assertion, []string{"any request id"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion SubjectConfirmation one of the possible request IDs ([any request id])"))

	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "wrong/acs/url"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion SubjectConfirmation Recipient is not https://15661444.ngrok.io/saml2/acs"))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = TimeNow().Add(-1 * time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion SubjectConfirmationData is expired"))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.NotBefore = TimeNow().Add(time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion Conditions is not yet valid"))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.NotOnOrAfter = TimeNow().Add(-1 * time.Hour)
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion Conditions is expired"))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	assertion.Conditions.AudienceRestrictions[0].Audience.Value = "not/our/metadata/url"
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, is.Error(err, "assertion Conditions AudienceRestriction does not contain \"https://15661444.ngrok.io/saml2/metadata\""))
	assertion = Assertion{}
	xml.Unmarshal(assertionBuf, &assertion)

	// Not having an audience is not an error
	assertion.Conditions.AudienceRestrictions = []AudienceRestriction{}
	err = s.validateAssertion(&assertion, []string{"id-9e61753d64e928af5a7a341a97f420c9"}, TimeNow())
	assert.Check(t, err)
}

func TestXswPermutationOneIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationOneIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"id-d40c15c104b52691eccf0a2a5c8a15595be75423"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Missing signature referencing the top-level element"))
}

func TestXswPermutationTwoIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestSPCanHandleOneloginResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationTwoIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 UTC 2006", "Tue Jan 5 17:53:12 UTC 2016")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("https://29ee6d2e.ngrok.io/saml/metadata"),
		AcsURL:      mustParseURL("https://29ee6d2e.ngrok.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"id-d40c15c104b52691eccf0a2a5c8a15595be75423"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Missing signature referencing the top-level element"))
}

func TestXswPermutationThreeIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationThreeIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	// Because this permutation contains an unsigned assertion as child of the response
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"either the Response or Assertion must be signed"))
}

func TestXswPermutationFourIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationFourIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	// Because this permutation contains an unsigned assertion as child of the response
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"either the Response or Assertion must be signed"))
}

func TestXswPermutationFiveIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationFiveIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Missing signature referencing the top-level element"))
}

func TestXswPermutationSixIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationSixIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Missing signature referencing the top-level element"))
}

func TestXswPermutationSevenIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationSevenIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T14:12:57Z")
		return rv
	}())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	// It's the assertion signature that can't be verified. The error message is generic and always mentions Response
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Signature could not be verified"))
}

func TestXswPermutationEightIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationEightIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T14:12:57Z")
		return rv
	}())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	// It's the assertion signature that can't be verified. The error message is generic and always mentions Response
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Signature could not be verified"))
}

func TestXswPermutationNineIsRejected(t *testing.T) {
	test := NewServiceProviderTest(t)
	idpMetadata := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	respStr := golden.Get(t, "TestXswPermutationNineIsRejected_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}
	Clock = dsig.NewFakeClockAt(func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T14:12:57Z")
		return rv
	}())

	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(respStr))
	_, err = s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	// It's the assertion signature that can't be verified. The error message is generic and always mentions Response
	assert.Check(t, is.Error(err.(*InvalidResponseError).PrivateErr,
		"cannot validate signature on Response: Missing signature referencing the top-level element"))
}

func TestSPRealWorldKeyInfoHasRSAPublicKeyNotX509Cert(t *testing.T) {
	// This is a real world SAML response that we observed. It contains <ds:RSAKeyValue> elements
	idpMetadata := golden.Get(t, "TestSPRealWorldKeyInfoHasRSAPublicKeyNotX509Cert_idp_metadata")
	respStr := golden.Get(t, "TestSPRealWorldKeyInfoHasRSAPublicKeyNotX509Cert_response")
	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Fri Apr 21 13:12:51 UTC 2017")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())
	s := ServiceProvider{
		Key:         mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey),
		Certificate: mustParseCertificate(golden.Get(t, "cert_2017.pem")),
		MetadataURL: mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/metadata"),
		AcsURL:      mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(respStr))
	_, err = s.ParseResponse(&req, []string{"id-3992f74e652d89c3cf1efd6c7e472abaac9bc917"})
	if err != nil {
		assert.Check(t, err.(*InvalidResponseError).PrivateErr)
	}
	assert.Check(t, err)
}

func TestSPRealWorldAssertionSignedNotResponse(t *testing.T) {
	// This is a real world SAML response that we observed. It contains <ds:RSAKeyValue> elements rather than
	// a certificate in the response.
	idpMetadata := golden.Get(t, "TestSPRealWorldAssertionSignedNotResponse_idp_metadata")
	respStr := golden.Get(t, "TestSPRealWorldAssertionSignedNotResponse_response")

	TimeNow = func() time.Time {
		rv, _ := time.Parse("Mon Jan 2 15:04:05 MST 2006", "Fri Apr 21 13:12:51 UTC 2017")
		return rv
	}
	Clock = dsig.NewFakeClockAt(TimeNow())

	s := ServiceProvider{
		Key:         mustParsePrivateKey(golden.Get(t, "key_2017.pem")).(*rsa.PrivateKey),
		Certificate: mustParseCertificate(golden.Get(t, "cert_2017.pem")),
		MetadataURL: mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/metadata"),
		AcsURL:      mustParseURL("https://preview.docrocket-ross.test.octolabs.io/saml/acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(idpMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(respStr))
	_, err = s.ParseResponse(&req, []string{"id-3992f74e652d89c3cf1efd6c7e472abaac9bc917"})
	if err != nil {
		assert.Check(t, err.(*InvalidResponseError).PrivateErr)
	}
	assert.Check(t, err)
}

func TestServiceProviderCanHandleSignedAssertionsResponse(t *testing.T) {
	test := NewServiceProviderTest(t)

	// Note: This test uses an actual response from onelogin, submitted by a user.
	// However, the test data below isn't actually valid -- the issue instant is
	// before the certificate's issued time. In order to preserve this test data and
	// signatures, we assign a different time to Clock, used by xmldsig than to
	// TimeNow which is used to verify the issue time of the SAML assertion.

	Clock = dsig.NewFakeClockAt(func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T14:12:57Z")
		return rv
	}())
	TimeNow = func() time.Time {
		rv, _ := time.Parse(timeFormat, "2014-07-17T01:02:59Z")
		return rv
	}

	SamlResponse := golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_response")
	test.IDPMetadata = golden.Get(t, "TestServiceProviderCanHandleSignedAssertionsResponse_IDPMetadata")
	s := ServiceProvider{
		Key:         test.Key,
		Certificate: test.Certificate,
		MetadataURL: mustParseURL("http://sp.example.com/demo1/metadata.php"),
		AcsURL:      mustParseURL("http://sp.example.com/demo1/index.php?acs"),
		IDPMetadata: &EntityDescriptor{},
	}
	err := xml.Unmarshal(test.IDPMetadata, &s.IDPMetadata)
	assert.Check(t, err)

	req := http.Request{PostForm: url.Values{}}
	req.PostForm.Set("SAMLResponse", string(SamlResponse))
	assertion, err := s.ParseResponse(&req, []string{"ONELOGIN_4fee3b046395c4e751011e97f8900b5273d56685"})
	if err != nil {
		t.Logf("%s", err.(*InvalidResponseError).PrivateErr)
	}
	assert.Check(t, err)

	assert.Check(t, is.Equal("_ce3d2948b4cf20146dee0a0b3dd6f69b6cf86f62d7", assertion.Subject.NameID.Value))
	assert.Check(t, is.DeepEqual([]Attribute{
		{
			Name:       "uid",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "test",
				},
			},
		},
		{
			Name:       "mail",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "test@example.com",
				},
			},
		},
		{
			Name:       "eduPersonAffiliation",
			NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
			Values: []AttributeValue{
				{
					Type:  "xs:string",
					Value: "users",
				},
				{
					Type:  "xs:string",
					Value: "examplerole1",
				},
			},
		},
	}, assertion.AttributeStatements[0].Attributes))
}

func TestSPResponseWithNoIssuer(t *testing.T) {
	test := NewServiceProviderTest(t)

	// This test case for the IdP response with no <Issuer> element. SAML standard says
	// that the <Issuer> element MAY be omitted in the <Response> (but MUST present in the <Assertion>).

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

	// Response with no <Issuer> (modified ServiceProviderTest.SamlResponse)
	samlResponse := golden.Get(t, "TestSPResponseWithNoIssuer_response")
	req.PostForm.Set("SAMLResponse", base64.StdEncoding.EncodeToString(samlResponse))
	_, err = s.ParseResponse(&req, []string{"id-9e61753d64e928af5a7a341a97f420c9"})
	assert.Check(t, err)
}
