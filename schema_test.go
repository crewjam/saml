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

func compare(c *C, doc *etree.Document, input string, expected string) {
	elem := doc.SelectElement("saml:Attribute")
	// fails to parse with the evil injection unescaped (nil)
	if elem != nil {
		actual := elem.SelectAttr("Name")
		c.Assert(actual.Value, Equals, expected)
	}
}

func (test *SchemaTest) TestXMLCanonicalizationVuln(c *C) {
	maliciousInputUnescaped := "<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"user.com<!-- vuln if substring returns -->evil.com\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>"
	maliciousInputEscaped := "<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"user.com&lt;!-- vuln if substring returns --&gt;evil.com\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>"
	expected := "user.com<!-- vuln if substring returns -->evil.com"

	// without canonicalization
	doc := etree.NewDocument()
	compare(c, doc, maliciousInputUnescaped, expected)
	compare(c, doc, maliciousInputEscaped, expected)

	// with canonicalization
	doc = etree.NewDocument()
	doc.WriteSettings = etree.WriteSettings{
		CanonicalAttrVal: true,
		CanonicalEndTags: true,
		CanonicalText:    true,
	}
	compare(c, doc, maliciousInputUnescaped, expected)
	compare(c, doc, maliciousInputEscaped, expected)
}
