package saml

import (
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const issuerFixture = `<saml:Issuer xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">https://idp.example.com/</saml:Issuer>`

// assertSignatureFollowsIssuer checks that the first two children of el are
// Issuer and the signature fixture, the order the SAML schema requires.
func assertSignatureFollowsIssuer(t *testing.T, el *etree.Element) {
	t.Helper()
	children := el.ChildElements()
	assert.Assert(t, len(children) >= 2, "%d children", len(children))
	assert.Check(t, is.Equal("Issuer", children[0].Tag))
	assertIsSigFixture(t, children[1])
}

func TestProtocolMessageSignatureRoundTrips(t *testing.T) {
	const samlp = `xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
	const status = `<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`
	header := ` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">` + issuerFixture + sigFixture

	type testCase struct {
		name      string
		input     string
		value     interface{}
		signature func() *etree.Element
	}
	var testCases []testCase
	add := func(name, input string, value interface{}, signature func() *etree.Element) {
		testCases = append(testCases, testCase{name, input, value, signature})
	}

	authnRequest := &AuthnRequest{}
	add("AuthnRequest", `<samlp:AuthnRequest `+samlp+header+`</samlp:AuthnRequest>`,
		authnRequest, func() *etree.Element { return authnRequest.Signature })
	logoutRequest := &LogoutRequest{}
	add("LogoutRequest", `<samlp:LogoutRequest `+samlp+header+
		`<saml:NameID xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">alice</saml:NameID></samlp:LogoutRequest>`,
		logoutRequest, func() *etree.Element { return logoutRequest.Signature })
	logoutResponse := &LogoutResponse{}
	add("LogoutResponse", `<samlp:LogoutResponse `+samlp+header+status+`</samlp:LogoutResponse>`,
		logoutResponse, func() *etree.Element { return logoutResponse.Signature })
	artifactResolve := &ArtifactResolve{}
	add("ArtifactResolve", `<samlp:ArtifactResolve `+samlp+header+
		`<samlp:Artifact>AAQAAA==</samlp:Artifact></samlp:ArtifactResolve>`,
		artifactResolve, func() *etree.Element { return artifactResolve.Signature })
	artifactResponse := &ArtifactResponse{}
	add("ArtifactResponse", `<samlp:ArtifactResponse `+samlp+header+status+`</samlp:ArtifactResponse>`,
		artifactResponse, func() *etree.Element { return artifactResponse.Signature })
	response := &Response{}
	add("Response", `<samlp:Response `+samlp+header+status+`</samlp:Response>`,
		response, func() *etree.Element { return response.Signature })
	assertion := &Assertion{}
	add("Assertion", `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`+header+`</saml:Assertion>`,
		assertion, func() *etree.Element { return assertion.Signature })

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			assert.NilError(t, xml.Unmarshal([]byte(tc.input), tc.value))
			assertIsSigFixture(t, tc.signature())
			assertSignatureFollowsIssuer(t, marshalAndParse(t, tc.value))
		})
	}
}

func TestResponseEncryptedAssertionRoundTrips(t *testing.T) {
	input := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">` +
		issuerFixture + sigFixture +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>` +
		`<saml:EncryptedAssertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"><xenc:CipherData><xenc:CipherValue>Y2lwaGVy</xenc:CipherValue></xenc:CipherData></xenc:EncryptedData>` +
		`</saml:EncryptedAssertion></samlp:Response>`

	var response Response
	assert.NilError(t, xml.Unmarshal([]byte(input), &response))
	assert.Assert(t, response.EncryptedAssertion != nil)
	assert.Check(t, is.Equal("saml", response.EncryptedAssertion.Space))
	assert.Check(t, is.Equal("Y2lwaGVy", response.EncryptedAssertion.FindElement(".//CipherValue").Text()))

	root := marshalAndParse(t, &response)
	assertSignatureFollowsIssuer(t, root)
	children := root.ChildElements()
	assert.Assert(t, is.Len(children, 4))
	assert.Check(t, is.Equal("Status", children[2].Tag))
	encrypted := children[3]
	assert.Check(t, is.Equal("EncryptedAssertion", encrypted.Tag))
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:assertion", encrypted.NamespaceURI()))
	assert.Check(t, is.Equal("Y2lwaGVy", encrypted.FindElement(".//CipherValue").Text()))
}

func TestProtocolMessageWithoutSignatureHasNilSignature(t *testing.T) {
	var response Response
	assert.NilError(t, xml.Unmarshal([]byte(
		`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">`+
			issuerFixture+`</samlp:Response>`), &response))
	assert.Check(t, response.Signature == nil)
	assert.Check(t, response.EncryptedAssertion == nil)
}
