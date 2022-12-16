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

func TestRequestedAuthnContext(t *testing.T) {
	expected := RequestedAuthnContext{
		Comparison: "comparison",
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:RequestedAuthnContext Comparison="comparison"><saml:AuthnContextClassRef/></samlp:RequestedAuthnContext>`,
		string(x)))
}

func TestArtifactResolveElement(t *testing.T) {
	issueInstant := time.Date(2020, 7, 21, 12, 30, 45, 0, time.UTC)
	expected := ArtifactResolve{
		ID:           "index",
		Version:      "version",
		IssueInstant: issueInstant,
		// Signature    *etree.Element
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:ArtifactResolve xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="index" Version="version" IssueInstant="2020-07-21T12:30:45Z"><samlp:Artifact/></samlp:ArtifactResolve>`,
		string(x)))

	var actual ArtifactResolve
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))

	x, err = xml.Marshal(expected)
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<ArtifactResolve xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="index" Version="version" IssueInstant="2020-07-21T12:30:45Z"><Artifact xmlns="urn:oasis:names:tc:SAML:2.0:protocol"></Artifact></ArtifactResolve>`,
		string(x)))
}

func TestArtifactResolveSoapRequest(t *testing.T) {
	issueInstant := time.Date(2020, 7, 21, 12, 30, 45, 0, time.UTC)
	expected := ArtifactResolve{
		ID:           "index",
		Version:      "version",
		IssueInstant: issueInstant,
		// Signature    *etree.Element
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.SoapRequest())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"><soapenv:Body><samlp:ArtifactResolve xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="index" Version="version" IssueInstant="2020-07-21T12:30:45Z"><samlp:Artifact/></samlp:ArtifactResolve></soapenv:Body></soapenv:Envelope>`,
		string(x)))
}

func TestArtifactResponseElement(t *testing.T) {
	issueInstant := time.Date(2020, 7, 21, 12, 30, 45, 0, time.UTC)
	status := Status{
		XMLName: xml.Name{
			Space: "urn:oasis:names:tc:SAML:2.0:protocol",
			Local: "Status",
		},
		StatusCode: StatusCode{
			XMLName: xml.Name{
				Space: "urn:oasis:names:tc:SAML:2.0:protocol",
				Local: "StatusCode",
			},
			Value: "value",
		},
	}
	expected := ArtifactResponse{
		ID:           "index",
		InResponseTo: "ID",
		Version:      "version",
		IssueInstant: issueInstant,
		Status:       status,
		Response: Response{
			ID:           "index",
			InResponseTo: "ID",
			Version:      "version",
			Destination:  "destination",
			Consent:      "consent",
			Status:       status,
			IssueInstant: issueInstant,
		},
		// Signature *etree.Element
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:ArtifactResponse xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="index" InResponseTo="ID" Version="version" IssueInstant="2020-07-21T12:30:45Z"><samlp:Status><samlp:StatusCode Value="value"/></samlp:Status><samlp:Response xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="index" InResponseTo="ID" Version="version" IssueInstant="2020-07-21T12:30:45Z" Destination="destination" Consent="consent"><samlp:Status><samlp:StatusCode Value="value"/></samlp:Status></samlp:Response></samlp:ArtifactResponse>`,
		string(x)))

	var actual ArtifactResponse
	err = xml.Unmarshal(x, &actual)
	assert.Check(t, err)
	assert.Check(t, is.DeepEqual(expected, actual))

	x, err = xml.Marshal(expected)
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="index" InResponseTo="ID" Version="version" IssueInstant="2020-07-21T12:30:45Z"><Status xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><StatusCode xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Value="value"></StatusCode></Status><Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ID="index" InResponseTo="ID" Version="version" IssueInstant="2020-07-21T12:30:45Z" Destination="destination" Consent="consent"><Status xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><StatusCode xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Value="value"></StatusCode></Status></Response></ArtifactResponse>`,
		string(x)))
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
