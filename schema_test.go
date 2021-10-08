package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
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
	assert.Check(t, err)
	assert.Check(t, is.Equal("<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"TestName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>",
		string(x)))

	var actual Attribute
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))
}

func TestNameIDFormat(t *testing.T) {
	var emptyString string
	el := NameIDPolicy{
		Format: &emptyString,
	}
	doc := etree.NewDocument()
	doc.SetRoot(el.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal("<samlp:NameIDPolicy/>",
		string(x)))
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
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<saml:AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionIndex="index" SessionNotOnOrAfter="2020-07-22T15:00:00Z"><saml:AuthnContext/></saml:AuthnStatement>`,
		string(x)))

	var actual AuthnStatement
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))

	x, err = xml.Marshal(expected)
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionIndex="index" SessionNotOnOrAfter="2020-07-22T15:00:00Z"><AuthnContext></AuthnContext></AuthnStatement>`,
		string(x)))
}

func TestAuthnStatementMarshalWithoutSessionNotOnOrAfter(t *testing.T) {
	authnInstant := time.Date(2020, 7, 21, 12, 30, 45, 0, time.UTC)
	expected := AuthnStatement{
		AuthnInstant:        authnInstant,
		SessionIndex:        "index",
		SessionNotOnOrAfter: nil,
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<saml:AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionIndex="index"><saml:AuthnContext/></saml:AuthnStatement>`,
		string(x)))

	var actual AuthnStatement
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))
}

func TestLogoutRequestXMLRoundTrip(t *testing.T) {
	issueInstant := time.Date(2021, 10, 8, 12, 30, 0, 0, time.UTC)
	notOnOrAfter := time.Date(2021, 10, 8, 12, 35, 0, 0, time.UTC)
	expected := LogoutRequest{
		ID:           "request-id",
		Version:      "2.0",
		IssueInstant: issueInstant,
		NotOnOrAfter: &notOnOrAfter,
		Issuer: &Issuer{
			XMLName: xml.Name{
				Space: "urn:oasis:names:tc:SAML:2.0:assertion",
				Local: "Issuer",
			},
			Value: "uri:issuer",
		},
		NameID: &NameID{
			Value: "name-id",
		},
		SessionIndex: &SessionIndex{
			Value: "index",
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-id" Version="2.0" IssueInstant="2021-10-08T12:30:00Z" NotOnOrAfter="2021-10-08T12:35:00Z"><saml:Issuer>uri:issuer</saml:Issuer><saml:NameID>name-id</saml:NameID><samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">index</samlp:SessionIndex></samlp:LogoutRequest>`,
		string(x)))

	var actual LogoutRequest
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))

	x, err = xml.Marshal(expected)
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-id" Version="2.0" IssueInstant="2021-10-08T12:30:00Z" NotOnOrAfter="2021-10-08T12:35:00Z" Destination=""><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="" SPNameQualifier="" Format="" SPProvidedID="">uri:issuer</Issuer><NameID NameQualifier="" SPNameQualifier="" Format="" SPProvidedID="">name-id</NameID><SessionIndex>index</SessionIndex></LogoutRequest>`,
		string(x)))
}

func TestLogoutRequestMarshalWithoutNotOnOrAfter(t *testing.T) {
	issueInstant := time.Date(2021, 10, 8, 12, 30, 0, 0, time.UTC)
	expected := LogoutRequest{
		ID:           "request-id",
		Version:      "2.0",
		IssueInstant: issueInstant,
		Issuer: &Issuer{
			XMLName: xml.Name{
				Space: "urn:oasis:names:tc:SAML:2.0:assertion",
				Local: "Issuer",
			},
			Value: "uri:issuer",
		},
		NameID: &NameID{
			Value: "name-id",
		},
		SessionIndex: &SessionIndex{
			Value: "index",
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:LogoutRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="request-id" Version="2.0" IssueInstant="2021-10-08T12:30:00Z"><saml:Issuer>uri:issuer</saml:Issuer><saml:NameID>name-id</saml:NameID><samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">index</samlp:SessionIndex></samlp:LogoutRequest>`,
		string(x)))

	var actual LogoutRequest
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))
}
