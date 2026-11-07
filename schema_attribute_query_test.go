package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

func testAttributeQuery() *AttributeQuery {
	return &AttributeQuery{
		ID:           "id-query",
		Version:      "2.0",
		IssueInstant: time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC),
		Destination:  "https://idp.example.com/saml/aa",
		Issuer:       &Issuer{Value: "https://sp.example.com/saml/metadata"},
		Subject: &Subject{NameID: &NameID{
			Format: string(PersistentNameIDFormat),
			Value:  "alice",
		}},
		Attributes: []Attribute{
			{Name: "urn:oid:0.9.2342.19200300.100.1.3", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"},
			{Name: "eduPersonAffiliation", Values: []AttributeValue{{Type: "xs:string", Value: "staff"}}},
		},
	}
}

func TestAttributeQueryElement(t *testing.T) {
	el := testAttributeQuery().SoapRequest()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToString()
	assert.NilError(t, err)

	// Re-parse, so that every element is checked by the namespace its
	// prefix resolves to rather than by the prefix itself.
	doc = etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(buf))
	root := doc.Root()
	assert.Equal(t, root.NamespaceURI(), soapEnvelopeNamespace)
	assert.Equal(t, root.Tag, "Envelope")
	body, err := findOneChild(root, soapEnvelopeNamespace, "Body")
	assert.NilError(t, err)
	queryEl, err := findOneChild(body, "urn:oasis:names:tc:SAML:2.0:protocol", "AttributeQuery")
	assert.NilError(t, err)
	assert.Equal(t, queryEl.SelectAttrValue("ID", ""), "id-query")
	assert.Equal(t, queryEl.SelectAttrValue("Destination", ""), "https://idp.example.com/saml/aa")
	assert.Equal(t, queryEl.SelectAttrValue("IssueInstant", ""), "2014-01-01T00:00:00Z")

	children := queryEl.ChildElements()
	assert.Equal(t, len(children), 4)
	for i, tag := range []string{"Issuer", "Subject", "Attribute", "Attribute"} {
		assert.Equal(t, children[i].NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:assertion")
		assert.Equal(t, children[i].Tag, tag)
	}
	nameID := children[1].FindElement("NameID")
	assert.Assert(t, nameID != nil)
	assert.Equal(t, nameID.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:assertion")
	assert.Equal(t, nameID.Text(), "alice")
	assert.Equal(t, nameID.SelectAttrValue("Format", ""), string(PersistentNameIDFormat))
	value := children[3].FindElement("AttributeValue")
	assert.Assert(t, value != nil)
	assert.Equal(t, value.Text(), "staff")
}

func TestAttributeQueryXMLRoundTrip(t *testing.T) {
	want := testAttributeQuery()
	buf, err := xml.Marshal(want)
	assert.NilError(t, err)

	var got AttributeQuery
	assert.NilError(t, xml.Unmarshal(buf, &got))
	assert.Equal(t, got.ID, want.ID)
	assert.Assert(t, got.IssueInstant.Equal(want.IssueInstant))
	assert.Equal(t, got.Destination, want.Destination)
	assert.Equal(t, got.Issuer.Value, want.Issuer.Value)
	assert.Check(t, is.DeepEqual(got.Subject.NameID, want.Subject.NameID))
	assert.Equal(t, len(got.Attributes), 2)
	assert.Equal(t, got.Attributes[0].Name, want.Attributes[0].Name)
	assert.Equal(t, got.Attributes[1].Values[0].Value, "staff")
}
