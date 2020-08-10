package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"github.com/stretchr/testify/assert"
)

func TestAttributeXMLRoundTrip(t *testing.T) {
	expected := Attribute{
		FriendlyName: "TestFriendlyName",
		Name:         "TestName",
		NameFormat:   "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		Values: []AttributeValue{{
			Type:  "xs:string",
			Value: "test",
		}},
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.NoError(t, err)
	assert.Equal(t,
		"<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"TestName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>",
		string(x))

	var actual Attribute
	err = xml.Unmarshal(x, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)
}

func TestNameIDFormat(t *testing.T) {
	var emptyString string
	el := NameIDPolicy{
		Format: &emptyString,
	}
	doc := etree.NewDocument()
	doc.SetRoot(el.Element())
	x, err := doc.WriteToBytes()
	assert.NoError(t, err)
	assert.Equal(t,
		"<samlp:NameIDPolicy/>",
		string(x))
}

func TestAuthnStatementXMLRoundTrip(t *testing.T) {
	authnInstant := time.Date(2020, 7, 21, 12, 30, 45, 0, time.UTC)
	sessionNotOnOrAfter := time.Date(2020, 7, 22, 15, 0, 0, 0, time.UTC)
	expected := AuthnStatement{
		AuthnInstant:        authnInstant,
		SessionIndex:        "index",
		SessionNotOnOrAfter: &sessionNotOnOrAfter,
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.NoError(t, err)
	assert.Equal(t,
		`<saml:AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionIndex="index" SessionNotOnOrAfter="2020-07-22T15:00:00Z"><saml:AuthnContext/></saml:AuthnStatement>`,
		string(x))

	var actual AuthnStatement
	err = xml.Unmarshal(x, &actual)
	assert.NoError(t, err)
	assert.Equal(t, expected, actual)

	x, err = xml.Marshal(expected)
	assert.NoError(t, err)
	assert.Equal(t,
		`<AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionIndex="index" SessionNotOnOrAfter="2020-07-22T15:00:00Z"><AuthnContext></AuthnContext></AuthnStatement>`,
		string(x))
}
