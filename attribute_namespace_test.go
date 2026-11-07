package saml

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// unmarshalForTest parses doc and reads its root into v the way the service
// provider reads a message it received.
func unmarshalForTest(t *testing.T, doc string, v interface{}) {
	t.Helper()
	d := etree.NewDocument()
	assert.NilError(t, d.ReadFromString(doc))
	assert.NilError(t, unmarshalElement(d.Root(), v))
}

const assertionNS = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"`

// A namespace declaration is not an attribute. encoding/xml reports
// xmlns:Name="..." as an attribute named Name, and exclusive
// canonicalization drops declarations that nothing uses, so one added to a
// signed element would otherwise replace the value of the field without
// invalidating the signature.
func TestAttributeNameIgnoresNamespaceDeclaration(t *testing.T) {
	var a Attribute
	unmarshalForTest(t, `<saml:Attribute `+assertionNS+` Name="displayName" xmlns:Name="role"><saml:AttributeValue>admin</saml:AttributeValue></saml:Attribute>`, &a)
	assert.Check(t, is.Equal(a.Name, "displayName"))
	assert.Assert(t, is.Len(a.Values, 1))
	assert.Check(t, is.Equal(a.Values[0].Value, "admin"))
}

func TestAttributeNameNotReadFromNamespaceDeclarationAlone(t *testing.T) {
	var a Attribute
	unmarshalForTest(t, `<saml:Attribute `+assertionNS+` xmlns:Name="role"/>`, &a)
	assert.Check(t, is.Equal(a.Name, ""))
}

func TestSubjectConfirmationDataNotOnOrAfterIgnoresNamespaceDeclaration(t *testing.T) {
	var d SubjectConfirmationData
	unmarshalForTest(t, `<saml:SubjectConfirmationData `+assertionNS+` NotOnOrAfter="2026-11-06T00:05:00Z" xmlns:NotOnOrAfter="2999-01-01T00:00:00Z"/>`, &d)
	assert.Check(t, d.NotOnOrAfter.Equal(time.Date(2026, 11, 6, 0, 5, 0, 0, time.UTC)), "got %s", d.NotOnOrAfter)
}

func TestSubjectConfirmationDataRecipientIgnoresNamespaceDeclaration(t *testing.T) {
	var d SubjectConfirmationData
	unmarshalForTest(t, `<saml:SubjectConfirmationData `+assertionNS+` Recipient="https://sp.example.com/acs" xmlns:Recipient="https://evil.example.com/acs"/>`, &d)
	assert.Check(t, is.Equal(d.Recipient, "https://sp.example.com/acs"))
}

func TestSubjectConfirmationDataInResponseToIgnoresNamespaceDeclaration(t *testing.T) {
	var d SubjectConfirmationData
	unmarshalForTest(t, `<saml:SubjectConfirmationData `+assertionNS+` InResponseTo="id-1" xmlns:InResponseTo="id-2"/>`, &d)
	assert.Check(t, is.Equal(d.InResponseTo, "id-1"))
}

func TestConditionsNotOnOrAfterIgnoresNamespaceDeclaration(t *testing.T) {
	var c Conditions
	unmarshalForTest(t, `<saml:Conditions `+assertionNS+` NotOnOrAfter="2026-11-06T00:05:00Z" xmlns:NotOnOrAfter="2999-01-01T00:00:00Z"/>`, &c)
	assert.Check(t, c.NotOnOrAfter.Equal(time.Date(2026, 11, 6, 0, 5, 0, 0, time.UTC)), "got %s", c.NotOnOrAfter)
}

func TestSubjectConfirmationMethodIgnoresNamespaceDeclaration(t *testing.T) {
	var c SubjectConfirmation
	unmarshalForTest(t, `<saml:SubjectConfirmation `+assertionNS+` Method="urn:oasis:names:tc:SAML:2.0:cm:holder-of-key" xmlns:Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"/>`, &c)
	assert.Check(t, is.Equal(c.Method, "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"))
}

// A declaration on an ancestor is in scope for the element's children too,
// and must not leak into them either.
func TestAttributeNameIgnoresInheritedNamespaceDeclaration(t *testing.T) {
	var s AttributeStatement
	unmarshalForTest(t, `<saml:AttributeStatement `+assertionNS+` xmlns:Name="role"><saml:Attribute Name="displayName"/></saml:AttributeStatement>`, &s)
	assert.Assert(t, is.Len(s.Attributes, 1))
	assert.Check(t, is.Equal(s.Attributes[0].Name, "displayName"))
}

// An attribute in another namespace is not the SAML attribute of the same
// local name.
func TestAttributeNameRequiresUnqualifiedAttribute(t *testing.T) {
	var a Attribute
	unmarshalForTest(t, `<saml:Attribute `+assertionNS+` xmlns:x="urn:example:foreign" Name="displayName" x:Name="role"/>`, &a)
	assert.Check(t, is.Equal(a.Name, "displayName"))
}

// Fields read by namespace, and the prefixes documents normally use, are
// unaffected.
func TestNamespacedAttributesStillRead(t *testing.T) {
	var a Assertion
	unmarshalForTest(t, `<saml:Assertion `+assertionNS+` xmlns:xs="http://www.w3.org/2001/XMLSchema" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="id-1">
  <ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo/></ds:Signature>
  <saml:AttributeStatement><saml:Attribute Name="mail"><saml:AttributeValue xsi:type="xs:string">a@example.com</saml:AttributeValue></saml:Attribute></saml:AttributeStatement>
</saml:Assertion>`, &a)
	assert.Check(t, is.Equal(a.ID, "id-1"))
	assert.Assert(t, a.Signature != nil)
	assert.Check(t, is.Equal(a.Signature.Space, "ds"))
	assert.Assert(t, is.Len(a.AttributeStatements, 1))
	assert.Assert(t, is.Len(a.AttributeStatements[0].Attributes, 1))
	v := a.AttributeStatements[0].Attributes[0].Values
	assert.Assert(t, is.Len(v, 1))
	assert.Check(t, is.Equal(v[0].Type, "xs:string"))
	assert.Check(t, is.Equal(v[0].Value, "a@example.com"))
}

// A prefix that could be an attribute field's name is renamed, and the
// element that uses it is still read in the right namespace.
func TestRenamedPrefixKeepsElementNamespace(t *testing.T) {
	var a Assertion
	unmarshalForTest(t, `<ID:Assertion xmlns:ID="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ns0="urn:example:other" ID="id-1"><ID:Issuer>https://idp.example.com/</ID:Issuer><ns0:Issuer>other</ns0:Issuer></ID:Assertion>`, &a)
	assert.Check(t, is.Equal(a.ID, "id-1"))
	assert.Check(t, is.Equal(a.Issuer.Value, "https://idp.example.com/"))
}

// sanitizeAttributesForUnmarshal keeps prefixes that start with a lower case
// letter, which is safe only while no attribute field of a type the service
// provider unmarshals could be named that way.
func TestUnmarshalledAttributeFieldsStartUpperCase(t *testing.T) {
	seen := map[reflect.Type]bool{}
	var check func(t *testing.T, typ reflect.Type)
	check = func(t *testing.T, typ reflect.Type) {
		for typ.Kind() == reflect.Pointer || typ.Kind() == reflect.Slice || typ.Kind() == reflect.Array {
			typ = typ.Elem()
		}
		if typ.Kind() != reflect.Struct || seen[typ] {
			return
		}
		seen[typ] = true
		for i := 0; i < typ.NumField(); i++ {
			f := typ.Field(i)
			if !f.IsExported() {
				continue
			}
			tag := f.Tag.Get("xml")
			opts := strings.Split(tag, ",")
			isAttr := false
			for _, o := range opts[1:] {
				if o == "attr" {
					isAttr = true
				}
				if o == "any" && isAttr {
					t.Errorf("%s.%s: ,any,attr would read namespace declarations", typ, f.Name)
				}
			}
			if isAttr {
				name := opts[0]
				if strings.Contains(name, " ") {
					continue // namespace-qualified: matched by namespace URI
				}
				if name == "" {
					name = f.Name
				}
				if safeNamespacePrefix(name) {
					t.Errorf("%s.%s: attribute name %q starts with a lower case letter", typ, f.Name, name)
				}
			}
			check(t, f.Type)
		}
	}
	for _, v := range []interface{}{Response{}, Assertion{}, LogoutRequest{}, LogoutResponse{}, ArtifactResponse{}} {
		check(t, reflect.TypeOf(v))
	}
}

// End to end: a declaration added to an attribute of a validly signed
// assertion leaves the signature valid but must not change the attribute.
func TestParseXMLResponseIgnoresNamespaceDeclarationInSignedAssertion(t *testing.T) {
	e := spcovSetup(t)

	a := e.assertion()
	a.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{{
		Name:   "displayName",
		Values: []AttributeValue{{Value: "admin"}},
	}}}}
	signedAssertion := e.idpSign(t, a.Element())

	attrEl := signedAssertion.FindElement("//saml:Attribute")
	assert.Assert(t, attrEl != nil)
	attrEl.CreateAttr("xmlns:Name", "role")
	scdEl := signedAssertion.FindElement("//saml:SubjectConfirmationData")
	assert.Assert(t, scdEl != nil)
	scdEl.CreateAttr("xmlns:NotOnOrAfter", "2999-01-01T00:00:00Z")

	responseEl := e.response().Element()
	responseEl.AddChild(signedAssertion)
	buf := spcovSerialize(t, responseEl)

	assertion, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.NilError(t, err)
	assert.Assert(t, is.Len(assertion.AttributeStatements, 1))
	assert.Assert(t, is.Len(assertion.AttributeStatements[0].Attributes, 1))
	assert.Check(t, is.Equal(assertion.AttributeStatements[0].Attributes[0].Name, "displayName"))
	assert.Check(t, assertion.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter.Equal(spcovNow.Add(5*time.Minute)))
}
