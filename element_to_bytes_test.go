package saml

import (
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func mustFindElement(t *testing.T, xmlStr, path string) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	assert.Check(t, doc.ReadFromString(xmlStr))
	el := doc.FindElement(path)
	assert.Assert(t, el != nil, "cannot find %s", path)
	return el
}

// The serialized element must be well-formed XML on its own: every prefix
// it uses has to be declared, and the default namespace must be written as
// xmlns="..." rather than the invalid xmlns:="...".
func assertStandalone(t *testing.T, el *etree.Element) {
	t.Helper()
	buf, err := elementToBytes(el)
	assert.Check(t, err)
	assert.Check(t, !strings.Contains(string(buf), `xmlns:=`), "invalid default namespace declaration in %s", buf)

	doc := etree.NewDocument()
	assert.Check(t, doc.ReadFromBytes(buf))
	for _, child := range doc.FindElements("//*") {
		if child.Space != "" {
			assert.Check(t, child.NamespaceURI() != "", "prefix %q is not declared in %s", child.Space, buf)
		}
	}
}

// An assertion in the default namespace, declared on the enclosing Response
// (as FusionAuth sends it), must keep that namespace when serialized alone.
func TestElementToBytesInheritedDefaultNamespace(t *testing.T) {
	const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<Assertion ID="a"><Issuer>idp</Issuer><Subject><NameID>alice</NameID></Subject></Assertion>` +
		`</samlp:Response>`
	el := mustFindElement(t, response, "//Assertion")
	assertStandalone(t, el)

	var assertion Assertion
	assert.Assert(t, unmarshalElement(el, &assertion))
	assert.Check(t, is.Equal("idp", assertion.Issuer.Value))
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal("alice", assertion.Subject.NameID.Value))
}

// A prefix declared on an ancestor that differs from the element's own
// prefix (here ds:, declared only on the Response) must still be declared.
func TestElementToBytesInheritedForeignPrefix(t *testing.T) {
	const response = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
		`<saml:Assertion ID="a"><saml:Issuer>idp</saml:Issuer><ds:Signature><ds:SignedInfo/></ds:Signature>` +
		`<saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>` +
		`</samlp:Response>`
	el := mustFindElement(t, response, "//Assertion")
	assertStandalone(t, el)

	var assertion Assertion
	assert.Assert(t, unmarshalElement(el, &assertion))
	assert.Check(t, assertion.Signature != nil)
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal("alice", assertion.Subject.NameID.Value))
}

// In the artifact binding the SAML prefixes are often declared on the SOAP
// envelope. The assertion nested in the ArtifactResponse must still bind.
func TestElementToBytesArtifactResponseInSOAPEnvelope(t *testing.T) {
	const envelope = `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<soap:Body><samlp:ArtifactResponse ID="ar" InResponseTo="req"><samlp:Response ID="r"><saml:Issuer>idp</saml:Issuer>` +
		`<saml:Assertion ID="a"><saml:Issuer>idp</saml:Issuer><saml:Subject><saml:NameID>alice</saml:NameID></saml:Subject></saml:Assertion>` +
		`</samlp:Response></samlp:ArtifactResponse></soap:Body></soap:Envelope>`
	el := mustFindElement(t, envelope, "//ArtifactResponse")
	assertStandalone(t, el)

	var artifactResponse ArtifactResponse
	assert.Assert(t, unmarshalElement(el, &artifactResponse))
	assert.Check(t, is.Equal("req", artifactResponse.InResponseTo))
	assert.Assert(t, artifactResponse.Response.Assertion != nil)
	assert.Assert(t, artifactResponse.Response.Assertion.Subject != nil)
	assert.Check(t, is.Equal("alice", artifactResponse.Response.Assertion.Subject.NameID.Value))
}

// The nearest declaration of a prefix wins over one further out, and a
// declaration on the element itself is never overridden.
func TestElementToBytesNearestDeclarationWins(t *testing.T) {
	const doc = `<a xmlns:p="urn:outer" xmlns="urn:outer-default">` +
		`<b xmlns:p="urn:inner" xmlns="urn:inner-default"><c xmlns="urn:own"><p:d/></c></b></a>`
	el := mustFindElement(t, doc, "//c")
	assertStandalone(t, el)

	buf, err := elementToBytes(el)
	assert.Assert(t, err)
	out := etree.NewDocument()
	assert.Assert(t, out.ReadFromBytes(buf))
	assert.Check(t, is.Equal("urn:own", out.Root().NamespaceURI()))
	assert.Check(t, is.Equal("urn:inner", out.FindElement("//d").NamespaceURI()))
}
