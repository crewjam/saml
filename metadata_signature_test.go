package saml

import (
	"crypto/x509"
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// sigFixture is a ds:Signature with every prefix declared on itself.
const sigFixture = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#">` +
	`<ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/></ds:SignedInfo>` +
	`<ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue>` +
	`</ds:Signature>`

// assertIsSigFixture checks that el is sigFixture, prefixes included.
func assertIsSigFixture(t *testing.T, el *etree.Element) {
	t.Helper()
	assert.Assert(t, el != nil)
	assert.Check(t, is.Equal("ds", el.Space))
	assert.Check(t, is.Equal("Signature", el.Tag))
	assert.Check(t, is.Equal(dsig.Namespace, el.NamespaceURI()))
	value := el.FindElement("./SignatureValue")
	assert.Assert(t, value != nil)
	assert.Check(t, is.Equal("ds", value.Space))
	assert.Check(t, is.Equal("c2lnbmF0dXJl", value.Text()))
}

// marshalAndParse marshals v and parses the result with etree, failing on
// the junk encoding/xml produces for a raw *etree.Element.
func marshalAndParse(t *testing.T, v interface{}) *etree.Element {
	t.Helper()
	buf, err := xml.Marshal(v)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), "<Space>"), string(buf))
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf), string(buf))
	return doc.Root()
}

func TestMetadataSignatureRoundTripsAtEveryLevel(t *testing.T) {
	input := `<EntitiesDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata">` + sigFixture +
		`<EntityDescriptor entityID="https://example.com/">` + sigFixture +
		`<RoleDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</RoleDescriptor>` +
		`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</IDPSSODescriptor>` +
		`<SPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</SPSSODescriptor>` +
		`<AuthnAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</AuthnAuthorityDescriptor>` +
		`<AttributeAuthorityDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</AttributeAuthorityDescriptor>` +
		`<PDPDescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol">` + sigFixture + `</PDPDescriptor>` +
		`<AffiliationDescriptor affiliationOwnerID="https://example.com/">` + sigFixture + `</AffiliationDescriptor>` +
		`</EntityDescriptor></EntitiesDescriptor>`

	var entities EntitiesDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(input), &entities))
	assert.Assert(t, is.Len(entities.EntityDescriptors, 1))
	ed := entities.EntityDescriptors[0]

	signatures := map[string]*etree.Element{
		"EntitiesDescriptor":           entities.Signature,
		"EntityDescriptor":             ed.Signature,
		"RoleDescriptor":               ed.RoleDescriptors[0].Signature,
		"IDPSSODescriptor":             ed.IDPSSODescriptors[0].Signature,
		"SPSSODescriptor":              ed.SPSSODescriptors[0].Signature,
		"AuthnAuthorityDescriptor":     ed.AuthnAuthorityDescriptors[0].Signature,
		"AttributeAuthorityDescriptor": ed.AttributeAuthorityDescriptors[0].Signature,
		"PDPDescriptor":                ed.PDPDescriptors[0].Signature,
		"AffiliationDescriptor":        ed.AffiliationDescriptor.Signature,
	}
	for name, sig := range signatures {
		t.Run("unmarshal "+name, func(t *testing.T) { assertIsSigFixture(t, sig) })
	}

	root := marshalAndParse(t, entities)
	for _, path := range []string{
		".",
		"./EntityDescriptor",
		"./EntityDescriptor/RoleDescriptor",
		"./EntityDescriptor/IDPSSODescriptor",
		"./EntityDescriptor/SPSSODescriptor",
		"./EntityDescriptor/AuthnAuthorityDescriptor",
		"./EntityDescriptor/AttributeAuthorityDescriptor",
		"./EntityDescriptor/PDPDescriptor",
		"./EntityDescriptor/AffiliationDescriptor",
	} {
		t.Run("marshal "+path, func(t *testing.T) {
			parent := root.FindElement(path)
			assert.Assert(t, parent != nil)
			// the metadata schema puts ds:Signature first
			first := parent.ChildElements()[0]
			assertIsSigFixture(t, first)
		})
	}
}

func TestMetadataWithoutSignatureHasNilSignature(t *testing.T) {
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(
		`<EntityDescriptor xmlns="urn:oasis:names:tc:SAML:2.0:metadata" entityID="https://example.com/">`+
			`<IDPSSODescriptor protocolSupportEnumeration="urn:oasis:names:tc:SAML:2.0:protocol"/>`+
			`</EntityDescriptor>`), &ed))
	assert.Check(t, ed.Signature == nil)
	assert.Check(t, ed.IDPSSODescriptors[0].Signature == nil)

	buf, err := xml.Marshal(ed)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(buf), "Signature"), string(buf))
}

func TestMetadataSignatureKeepsPrefixDeclaredOnAncestor(t *testing.T) {
	// ADFS-style: the ds prefix is declared on EntityDescriptor, not on the
	// Signature, so the decoded Signature must declare it itself.
	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal([]byte(
		`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" entityID="https://example.com/">`+
			`<ds:Signature><ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue></ds:Signature>`+
			`</md:EntityDescriptor>`), &ed))
	assertIsSigFixture(t, ed.Signature)
	assert.Check(t, is.Equal(dsig.Namespace, ed.Signature.SelectAttrValue("xmlns:ds", "")))

	root := marshalAndParse(t, ed)
	assertIsSigFixture(t, root.ChildElements()[0])
}

func TestMetadataSignatureFromLargerDocumentDeclaresItsPrefix(t *testing.T) {
	// A Signature taken out of a document may rely on a prefix declared on
	// an ancestor that is not marshaled; the output must declare it.
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(
		`<root xmlns:ds="http://www.w3.org/2000/09/xmldsig#">`+
			`<ds:Signature><ds:SignatureValue>c2lnbmF0dXJl</ds:SignatureValue></ds:Signature>`+
			`</root>`))

	ed := EntityDescriptor{EntityID: "https://example.com/", Signature: doc.FindElement("//Signature")}
	root := marshalAndParse(t, ed)
	assertIsSigFixture(t, root.ChildElements()[0])
}

func TestSignedMetadataStillVerifiesAfterRoundTrip(t *testing.T) {
	test := NewIdentityProviderTest(t, applyKey)
	signed, err := test.IDP.SignedMetadata()
	assert.NilError(t, err)
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)

	var ed EntityDescriptor
	assert.NilError(t, xml.Unmarshal(buf, &ed))
	assert.Assert(t, ed.Signature != nil)

	root := marshalAndParse(t, ed)
	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{test.Certificate},
	})
	validationContext.Clock = dsig.NewFakeClockAt(test.Certificate.NotBefore)
	_, err = validationContext.Validate(root)
	assert.NilError(t, err)
}
