package saml

import (
	"encoding/xml"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
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
	// The saml prefix must be declared for the namespace-bound fields to unmarshal.
	el := expected.Element()
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	doc.SetRoot(el)
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal("<saml:Attribute FriendlyName=\"TestFriendlyName\" Name=\"TestName\" NameFormat=\"urn:oasis:names:tc:SAML:2.0:attrname-format:basic\" xmlns:saml=\"urn:oasis:names:tc:SAML:2.0:assertion\"><saml:AttributeValue xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns:xs=\"http://www.w3.org/2001/XMLSchema\" xsi:type=\"xs:string\">test</saml:AttributeValue></saml:Attribute>",
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
	assert.Check(t, is.Equal(`<AuthnStatement AuthnInstant="2020-07-21T12:30:45Z" SessionNotOnOrAfter="2020-07-22T15:00:00Z" SessionIndex="index"><AuthnContext xmlns="urn:oasis:names:tc:SAML:2.0:assertion"></AuthnContext></AuthnStatement>`,
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

func TestAuthenticatingAuthority(t *testing.T) {
	expected := AuthenticatingAuthority{
		Value: "value",
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<saml:AuthenticatingAuthority>value</saml:AuthenticatingAuthority>`,
		string(x)))
}

func TestAuthnContextNoAuthenticatingAuthority(t *testing.T) {
	expected := AuthnContext{
		AuthnContextClassRef: &AuthnContextClassRef{
			Value: "value",
		},
		AuthenticatingAuthorities: nil,
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<saml:AuthnContext><saml:AuthnContextClassRef>value</saml:AuthnContextClassRef></saml:AuthnContext>`,
		string(x)))
}

func TestAuthnContextMultiAuthenticatingAuthority(t *testing.T) {
	expected := AuthnContext{
		AuthnContextClassRef: &AuthnContextClassRef{
			Value: "value",
		},
		AuthenticatingAuthorities: []AuthenticatingAuthority{
			{Value: "value1"},
			{Value: "value2"},
		},
	}

	doc := etree.NewDocument()
	doc.SetRoot(expected.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<saml:AuthnContext><saml:AuthnContextClassRef>value</saml:AuthnContextClassRef><saml:AuthenticatingAuthority>value1</saml:AuthenticatingAuthority><saml:AuthenticatingAuthority>value2</saml:AuthenticatingAuthority></saml:AuthnContext>`,
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
	assert.Check(t, is.Equal(`<ArtifactResolve xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2020-07-21T12:30:45Z" ID="index" Version="version"><Artifact xmlns="urn:oasis:names:tc:SAML:2.0:protocol"></Artifact></ArtifactResolve>`,
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
	assert.Check(t, is.Equal(`<ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2020-07-21T12:30:45Z" ID="index" InResponseTo="ID" Version="version"><Status xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><StatusCode xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Value="value"></StatusCode></Status><Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2020-07-21T12:30:45Z" ID="index" InResponseTo="ID" Version="version" Destination="destination" Consent="consent"><Status xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><StatusCode xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Value="value"></StatusCode></Status></Response></ArtifactResponse>`,
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
	assert.Check(t, is.Equal(`<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2021-10-08T12:30:00Z" NotOnOrAfter="2021-10-08T12:35:00Z" ID="request-id" Version="2.0" Destination=""><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="" SPNameQualifier="" Format="" SPProvidedID="">uri:issuer</Issuer><NameID xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="" SPNameQualifier="" Format="" SPProvidedID="">name-id</NameID><SessionIndex>index</SessionIndex></LogoutRequest>`,
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

func TestAuthnContextUnmarshalAuthenticatingAuthority(t *testing.T) {
	input := `<saml:AuthnContext xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<saml:AuthnContextClassRef>value</saml:AuthnContextClassRef>` +
		`<saml:AuthenticatingAuthority>value1</saml:AuthenticatingAuthority>` +
		`<saml:AuthenticatingAuthority>value2</saml:AuthenticatingAuthority>` +
		`</saml:AuthnContext>`

	var actual AuthnContext
	assert.Check(t, xml.Unmarshal([]byte(input), &actual))
	assert.Check(t, is.DeepEqual(AuthnContext{
		AuthnContextClassRef: &AuthnContextClassRef{Value: "value"},
		AuthenticatingAuthorities: []AuthenticatingAuthority{
			{Value: "value1"},
			{Value: "value2"},
		},
	}, actual))
}

func TestRequestedAuthnContextMultipleClassRefs(t *testing.T) {
	const (
		classA = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"
		classB = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	)
	expectedXML := `<samlp:RequestedAuthnContext Comparison="minimum">` +
		`<saml:AuthnContextClassRef>` + classA + `</saml:AuthnContextClassRef>` +
		`<saml:AuthnContextClassRef>` + classB + `</saml:AuthnContextClassRef>` +
		`</samlp:RequestedAuthnContext>`

	r := RequestedAuthnContext{
		Comparison:            "minimum",
		AuthnContextClassRefs: []string{classA, classB},
		AuthnContextClassRef:  "ignored when AuthnContextClassRefs is set",
	}
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(expectedXML, string(x)))

	// Parsing keeps every value and sets the deprecated field to the first.
	in := `<samlp:RequestedAuthnContext xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ` +
		`xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" Comparison="minimum">` +
		`<saml:AuthnContextClassRef>` + classA + `</saml:AuthnContextClassRef>` +
		`<saml:AuthnContextClassRef>` + classB + `</saml:AuthnContextClassRef>` +
		`</samlp:RequestedAuthnContext>`
	var got RequestedAuthnContext
	assert.Check(t, xml.Unmarshal([]byte(in), &got))
	assert.Check(t, is.Equal("minimum", got.Comparison))
	assert.Check(t, is.DeepEqual([]string{classA, classB}, got.AuthnContextClassRefs))
	assert.Check(t, is.Equal(classA, got.AuthnContextClassRef))
	assert.Check(t, is.DeepEqual([]string{classA, classB}, got.ClassRefs()))

	// encoding/xml marshaling round-trips too.
	out, err := xml.Marshal(got)
	assert.Check(t, err)
	var again RequestedAuthnContext
	assert.Check(t, xml.Unmarshal(out, &again))
	assert.Check(t, is.DeepEqual(got.AuthnContextClassRefs, again.AuthnContextClassRefs))
}

func TestRequestedAuthnContextDeprecatedSingleClassRef(t *testing.T) {
	r := RequestedAuthnContext{
		Comparison:           "exact",
		AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password",
	}
	doc := etree.NewDocument()
	doc.SetRoot(r.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:RequestedAuthnContext Comparison="exact">`+
		`<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>`+
		`</samlp:RequestedAuthnContext>`, string(x)))
	assert.Check(t, is.DeepEqual([]string{"urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}, r.ClassRefs()))
}

func TestScopingElement(t *testing.T) {
	proxyCount := 2
	req := AuthnRequest{Scoping: &Scoping{
		ProxyCount: &proxyCount,
		IDPList: &IDPList{
			IDPEntries: []IDPEntry{
				{ProviderID: "https://idp1.example.com"},
				{ProviderID: "https://idp2.example.com", Name: "IDP 2", Loc: "https://idp2.example.com/sso"},
			},
			GetComplete: "https://gateway.example.com/idplist",
		},
		RequesterIDs: []string{"https://sp.example.com"},
	}}

	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:AuthnRequest xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="" Version="" IssueInstant="0001-01-01T00:00:00Z">`+
		`<samlp:Scoping ProxyCount="2">`+
		`<samlp:IDPList>`+
		`<samlp:IDPEntry ProviderID="https://idp1.example.com"/>`+
		`<samlp:IDPEntry ProviderID="https://idp2.example.com" Name="IDP 2" Loc="https://idp2.example.com/sso"/>`+
		`<samlp:GetComplete>https://gateway.example.com/idplist</samlp:GetComplete>`+
		`</samlp:IDPList>`+
		`<samlp:RequesterID>https://sp.example.com</samlp:RequesterID>`+
		`</samlp:Scoping>`+
		`</samlp:AuthnRequest>`, string(x)))

	// The element form parses back through the encoding/xml struct tags.
	var got AuthnRequest
	assert.Check(t, xml.Unmarshal(x, &got))
	assert.Assert(t, got.Scoping != nil)
	assert.Assert(t, got.Scoping.ProxyCount != nil)
	assert.Check(t, is.Equal(2, *got.Scoping.ProxyCount))
	assert.Assert(t, got.Scoping.IDPList != nil)
	assert.Check(t, is.Len(got.Scoping.IDPList.IDPEntries, 2))
	assert.Check(t, is.Equal("https://idp1.example.com", got.Scoping.IDPList.IDPEntries[0].ProviderID))
	assert.Check(t, is.Equal("IDP 2", got.Scoping.IDPList.IDPEntries[1].Name))
	assert.Check(t, is.Equal("https://idp2.example.com/sso", got.Scoping.IDPList.IDPEntries[1].Loc))
	assert.Check(t, is.Equal("https://gateway.example.com/idplist", got.Scoping.IDPList.GetComplete))
	assert.Check(t, is.DeepEqual([]string{"https://sp.example.com"}, got.Scoping.RequesterIDs))
}

func TestScopingElementMinimal(t *testing.T) {
	s := Scoping{IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: "https://idp.example.com"}}}}
	doc := etree.NewDocument()
	doc.SetRoot(s.Element())
	x, err := doc.WriteToBytes()
	assert.Check(t, err)
	assert.Check(t, is.Equal(`<samlp:Scoping><samlp:IDPList><samlp:IDPEntry ProviderID="https://idp.example.com"/></samlp:IDPList></samlp:Scoping>`, string(x)))
}
