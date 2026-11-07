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
	attributeQuery := &AttributeQuery{}
	add("AttributeQuery", `<samlp:AttributeQuery `+samlp+header+
		`<saml:Subject xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:NameID>alice</saml:NameID></saml:Subject></samlp:AttributeQuery>`,
		attributeQuery, func() *etree.Element { return attributeQuery.Signature })
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

func TestStatusDetailChildrenRoundTrip(t *testing.T) {
	input := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:outer="urn:outer" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">` +
		issuerFixture +
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Responder"/>` +
		`<samlp:StatusDetail xmlns:x="urn:x" xmlns="urn:default">` +
		`<own:Reason xmlns:own="urn:own" own:code="42">own prefix</own:Reason>` + // declared on itself
		"\n  " + // text between children is ignored
		`<x:Reason>prefix from StatusDetail</x:Reason>` +
		`<Reason>default namespace from StatusDetail</Reason>` +
		`<outer:Reason>prefix from Response</outer:Reason>` +
		`</samlp:StatusDetail></samlp:Status></samlp:Response>`

	type want struct{ space, uri, text string }
	wants := []want{
		{"own", "urn:own", "own prefix"},
		{"x", "urn:x", "prefix from StatusDetail"},
		{"", "urn:default", "default namespace from StatusDetail"},
		// outer is declared outside StatusDetail, so it gets a generated
		// prefix bound to the same namespace
		{"ns0", "urn:outer", "prefix from Response"},
	}
	check := func(t *testing.T, children []*etree.Element) {
		t.Helper()
		assert.Assert(t, is.Len(children, len(wants)))
		for i, w := range wants {
			assert.Check(t, is.Equal("Reason", children[i].Tag))
			assert.Check(t, is.Equal(w.space, children[i].Space))
			assert.Check(t, is.Equal(w.uri, children[i].NamespaceURI()))
			assert.Check(t, is.Equal(w.text, children[i].Text()))
		}
		assert.Check(t, is.Equal("42", children[0].SelectAttrValue("own:code", "")))
	}

	var response Response
	assert.NilError(t, xml.Unmarshal([]byte(input), &response))
	assert.Assert(t, response.Status.StatusDetail != nil)
	check(t, response.Status.StatusDetail.Children)

	root := marshalAndParse(t, &response)
	detail := root.FindElement("./Status/StatusDetail")
	assert.Assert(t, detail != nil)
	check(t, detail.ChildElements())
}

func TestStatusDetailMarshalsEtreeChildren(t *testing.T) {
	status := Status{
		StatusCode: StatusCode{Value: StatusResponder},
		StatusDetail: &StatusDetail{Children: []*etree.Element{
			etree.NewElement("plain"),
			func() *etree.Element {
				el := etree.NewElement("x:Cause")
				el.CreateAttr("xmlns:x", "urn:x")
				el.SetText("a < b")
				return el
			}(),
		}},
	}
	root := marshalAndParse(t, status)
	children := root.FindElement("./StatusDetail").ChildElements()
	assert.Assert(t, is.Len(children, 2))
	// an element with no namespace stays out of the protocol default namespace
	assert.Check(t, is.Equal("plain", children[0].Tag))
	assert.Check(t, is.Equal("", children[0].NamespaceURI()))
	assert.Check(t, is.Equal("Cause", children[1].Tag))
	assert.Check(t, is.Equal("urn:x", children[1].NamespaceURI()))
	assert.Check(t, is.Equal("a < b", children[1].Text()))
}
