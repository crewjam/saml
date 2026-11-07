package saml

import (
	"encoding/xml"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func TestAttributeValueComplexContent(t *testing.T) {
	// The ex: prefix is declared on the Attribute, outside the value.
	const doc = `<saml:Attribute xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:ex="urn:example:address" Name="address">
	  <saml:AttributeValue xsi:type="ex:AddressType"><ex:Street>1 Main St</ex:Street><ex:City lang="en">Springfield</ex:City></saml:AttributeValue>
	  <saml:AttributeValue xsi:type="xs:string">plain</saml:AttributeValue>
	  <saml:AttributeValue><saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">abc</saml:NameID></saml:AttributeValue>
	  <saml:AttributeValue xsi:nil="1"/>
	</saml:Attribute>`
	var attr Attribute
	assert.NilError(t, xml.Unmarshal([]byte(doc), &attr))
	assert.Assert(t, is.Len(attr.Values, 4))

	complexValue := attr.Values[0]
	assert.Check(t, is.Equal("ex:AddressType", complexValue.Type))
	assert.Check(t, is.Equal("", strings.TrimSpace(complexValue.Value)))
	// The XML stands on its own: its namespace is declared in it.
	content := etree.NewDocument()
	assert.NilError(t, content.ReadFromString("<root>"+complexValue.XML+"</root>"))
	street := content.FindElement("//Street")
	assert.Assert(t, street != nil, complexValue.XML)
	assert.Check(t, is.Equal("urn:example:address", street.NamespaceURI()))
	assert.Check(t, is.Equal("1 Main St", street.Text()))
	assert.Check(t, is.Equal("en", content.FindElement("//City").SelectAttrValue("lang", "")))

	// Simple values, NameIDs and nulls are read as before, without XML.
	assert.Check(t, is.DeepEqual(AttributeValue{Type: "xs:string", Value: "plain"}, attr.Values[1]))
	assert.Assert(t, attr.Values[2].NameID != nil)
	assert.Check(t, is.Equal("abc", attr.Values[2].NameID.Value))
	assert.Check(t, is.Equal("", attr.Values[2].XML))
	assert.Check(t, attr.Values[3].Nil)

	// Written out again, the complex content is kept.
	el := complexValue.Element()
	assert.Check(t, el.FindElement("./Street") != nil)
	var reread AttributeValue
	buf, err := elementToBytes(el)
	assert.NilError(t, err)
	assert.NilError(t, xml.Unmarshal(buf, &reread))
	assert.Check(t, is.Contains(reread.XML, "1 Main St"))
}

func TestAttributeValueInvalidNil(t *testing.T) {
	const doc = `<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="maybe"/>`
	var v AttributeValue
	assert.Check(t, xml.Unmarshal([]byte(doc), &v) != nil)
}
