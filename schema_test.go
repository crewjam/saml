package saml

import (
	"encoding/xml"

	"github.com/beevik/etree"
	. "gopkg.in/check.v1"
)

var _ = Suite(&SchemaTest{})

type SchemaTest struct {
}

func (test *SchemaTest) TestAttributeXMLRoundTrip(c *C) {
	expected := Attribute{
		FriendlyName: "TestFriendlyName",
		Name:         "TestName",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []AttributeValue{AttributeValue{
			Type:  "xs:string",
			Value: "test",
		}},
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	c.Assert(err, IsNil)
	c.Assert(string(x), Equals, "<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"TestName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>")

	var actual Attribute
	err = xml.Unmarshal(x, &actual)
	c.Assert(err, IsNil)
	c.Assert(actual, DeepEquals, expected)
}
