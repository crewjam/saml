package saml

import (
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func attributeValueParse(t *testing.T, s string) AttributeValue {
	t.Helper()
	var attr Attribute
	assert.NilError(t, xml.Unmarshal([]byte(s), &attr))
	assert.Assert(t, is.Len(attr.Values, 1))
	return attr.Values[0]
}

func attributeValueString(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	assert.NilError(t, err)
	return s
}

// saml-core §2.7.3.1.1: a null value is an empty <AttributeValue> carrying
// xsi:nil with a value of "true" or "1".
func TestAttributeValueNilParse(t *testing.T) {
	for _, v := range []string{"true", "1"} {
		got := attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Name="a">`+
			`<saml:AttributeValue xsi:nil="`+v+`"/></saml:Attribute>`)
		assert.Check(t, got.Nil, "xsi:nil=%q", v)
		assert.Check(t, is.Equal("", got.Value))
	}

	for _, v := range []string{"false", "0"} {
		got := attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" Name="a">`+
			`<saml:AttributeValue xsi:nil="`+v+`"/></saml:Attribute>`)
		assert.Check(t, !got.Nil, "xsi:nil=%q", v)
	}
}

// An empty element without xsi:nil is an empty string, not a null value.
func TestAttributeValueEmptyIsNotNil(t *testing.T) {
	got := attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="a"><saml:AttributeValue/></saml:Attribute>`)
	assert.Check(t, !got.Nil)
	assert.Check(t, is.Equal("", got.Value))

	el := (&AttributeValue{}).Element()
	assert.Check(t, el.SelectAttr("xsi:nil") == nil)
}

func TestAttributeValueNilRoundTrip(t *testing.T) {
	// Value is ignored for a null value: the element MUST be empty.
	av := AttributeValue{Nil: true, Value: "ignored", NameID: &NameID{Value: "ignored"}}
	el := av.Element()
	s := attributeValueString(t, el)
	assert.Check(t, is.Equal(`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:nil="true"/>`, s))

	got := attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="a">`+s+`</saml:Attribute>`)
	assert.Check(t, is.DeepEqual(AttributeValue{Nil: true}, got))

	// encoding/xml round trip too.
	buf, err := xml.Marshal(Attribute{Name: "a", Values: []AttributeValue{{Nil: true}}})
	assert.NilError(t, err)
	got = attributeValueParse(t, string(buf))
	assert.Check(t, got.Nil)
}

// saml-profiles §8.2.4: under the X.500/LDAP profile each <AttributeValue>
// carries x500:Encoding="LDAP" in the X500 profile namespace.
func TestAttributeValueEncodingRoundTrip(t *testing.T) {
	av := AttributeValue{Type: "xs:string", Encoding: X500EncodingLDAP, Value: "alice"}
	el := av.Element()
	s := attributeValueString(t, el)
	assert.Check(t, is.Equal(`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" `+
		`xmlns:x500="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" xsi:type="xs:string" x500:Encoding="LDAP">alice</saml:AttributeValue>`, s))
	attr := el.SelectAttr("x500:Encoding")
	assert.Assert(t, attr != nil)
	assert.Check(t, is.Equal(X500AttributeNamespace, attr.NamespaceURI()))

	got := attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="a">`+s+`</saml:Attribute>`)
	assert.Check(t, is.DeepEqual(av, got))

	// The prefix is not significant, only the namespace.
	got = attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:p="urn:oasis:names:tc:SAML:2.0:profiles:attribute:X500" Name="a">`+
		`<saml:AttributeValue p:Encoding="LDAP">v</saml:AttributeValue></saml:Attribute>`)
	assert.Check(t, is.Equal("LDAP", got.Encoding))

	// An unqualified Encoding attribute is not x500:Encoding.
	got = attributeValueParse(t, `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Name="a">`+
		`<saml:AttributeValue Encoding="LDAP">v</saml:AttributeValue></saml:Attribute>`)
	assert.Check(t, is.Equal("", got.Encoding))

	// Without Encoding nothing is written.
	el = (&AttributeValue{Value: "v"}).Element()
	assert.Check(t, el.SelectAttr("x500:Encoding") == nil)
	assert.Check(t, el.SelectAttr("xmlns:x500") == nil)

	// encoding/xml round trip too.
	buf, err := xml.Marshal(Attribute{Name: "a", Values: []AttributeValue{av}})
	assert.NilError(t, err)
	got = attributeValueParse(t, string(buf))
	assert.Check(t, is.Equal(X500EncodingLDAP, got.Encoding))
}

// saml-profiles §8.2.2: the FriendlyName SHOULD be one of the defined
// descriptors; for urn:oid:1.3.6.1.4.1.5923.1.1.1.9 that is
// eduPersonScopedAffiliation.
func TestAttributeValueIDPScopedAffiliationFriendlyName(t *testing.T) {
	test := idpcovNewTest(t)
	req := idpcovRequest(t, test)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		UserName:              "alice",
		UserScopedAffiliation: "member@example.com",
	}))
	var found bool
	for _, attr := range req.Assertion.AttributeStatements[0].Attributes {
		if attr.Name != "urn:oid:1.3.6.1.4.1.5923.1.1.1.9" {
			continue
		}
		found = true
		assert.Check(t, is.Equal("eduPersonScopedAffiliation", attr.FriendlyName))
	}
	assert.Check(t, found)
}
