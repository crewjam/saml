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
	  <saml:AttributeValue><foo:a xmlns:foo="urn:foo" xsi:type="ex:T"><foo:b/></foo:a></saml:AttributeValue>
	</saml:Attribute>`
	attr := parseAttribute(t, doc)
	assert.Assert(t, is.Len(attr.Values, 5))

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

	// A prefix declared on the child, and the prefix of a QName value
	// declared on an ancestor, both resolve in the XML, which declares
	// nothing else.
	foo := etree.NewDocument()
	assert.NilError(t, foo.ReadFromString(attr.Values[4].XML))
	a := foo.Root()
	assert.Check(t, is.Equal("a", a.Tag))
	assert.Check(t, is.Equal("urn:foo", a.NamespaceURI()))
	assert.Check(t, is.Equal("urn:foo", a.FindElement("b").NamespaceURI()))
	typ := a.SelectAttr("xsi:type")
	assert.Assert(t, typ != nil, attr.Values[4].XML)
	assert.Check(t, is.Equal("http://www.w3.org/2001/XMLSchema-instance", typ.NamespaceURI()))
	assert.Check(t, is.Equal("urn:example:address", a.SelectAttrValue("xmlns:ex", "")))
	assert.Check(t, !strings.Contains(attr.Values[4].XML, "_xmlns"), attr.Values[4].XML)

	// Written out again, the complex content is kept.
	el := complexValue.Element()
	assert.Check(t, el.FindElement("./Street") != nil)
	assert.Check(t, is.Contains(fillValues(t, el).XML, "1 Main St"))

	// Malformed XML set by a caller is left out.
	el = (&AttributeValue{Value: "x", XML: "<unclosed>"}).Element()
	assert.Check(t, is.Len(el.ChildElements(), 0))
	assert.Check(t, is.Equal("x", el.Text()))
}

// parseAttribute reads an Attribute as the ServiceProvider does.
func parseAttribute(t *testing.T, s string) Attribute {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(s))
	var attr Attribute
	assert.NilError(t, unmarshalElement(doc.Root(), &attr))
	assert.NilError(t, fillAttributeXML(doc.Root(), &attr))
	return attr
}

// fillValues reads the AttributeValue el as the ServiceProvider does.
func fillValues(t *testing.T, el *etree.Element) AttributeValue {
	t.Helper()
	attrEl := etree.NewElement("saml:Attribute")
	attrEl.CreateAttr("xmlns:saml", samlAssertionNamespace)
	attrEl.AddChild(el)
	buf, err := elementToBytes(attrEl)
	assert.NilError(t, err)
	attr := parseAttribute(t, string(buf))
	assert.Assert(t, is.Len(attr.Values, 1))
	return attr.Values[0]
}

func TestAttributeValueInvalidNil(t *testing.T) {
	const doc = `<AttributeValue xmlns="urn:oasis:names:tc:SAML:2.0:assertion"
	    xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xsi:nil="maybe"/>`
	var v AttributeValue
	assert.Check(t, xml.Unmarshal([]byte(doc), &v) != nil)
}
