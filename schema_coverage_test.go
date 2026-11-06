package saml

import (
	"bytes"
	"compress/flate"
	"encoding/xml"
	"io"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// schemacovTime is a millisecond-precision UTC timestamp so that it survives
// the Element() -> XML -> UnmarshalXML round trip unchanged.
var schemacovTime = time.Date(2015, 12, 1, 1, 57, 9, 123000000, time.UTC)

const (
	schemacovNS     = `xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"`
	schemacovSigXML = `<ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"/>`
)

// schemacovString serializes el as a document root and returns the XML text.
func schemacovString(t *testing.T, el *etree.Element) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	s, err := doc.WriteToString()
	assert.NilError(t, err)
	return s
}

// schemacovSig returns a fresh placeholder signature element.
func schemacovSig() *etree.Element {
	el := etree.NewElement("ds:Signature")
	el.CreateAttr("xmlns:ds", "http://www.w3.org/2000/09/xmldsig#")
	return el
}

// schemacovWrap wraps a fragment that uses the saml/samlp prefixes in a root
// element that declares them, so encoding/xml resolves namespaces correctly.
func schemacovWrap(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	root := etree.NewElement("root")
	root.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	root.CreateAttr("xmlns:samlp", "urn:oasis:names:tc:SAML:2.0:protocol")
	root.AddChild(el)
	return []byte(schemacovString(t, root))
}

func schemacovPtr[T any](v T) *T { return &v }

// TestSchemacovUnmarshalXMLBadTime feeds an unparseable time attribute to each
// UnmarshalXML implementation that converts RelaxedTime values, so the
// DecodeElement error branch is exercised.
func TestSchemacovUnmarshalXMLBadTime(t *testing.T) {
	cases := []struct {
		name string
		xml  string
		dst  any
	}{
		{"LogoutRequest", `<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &LogoutRequest{}},
		{"LogoutRequestNotOnOrAfter", `<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" NotOnOrAfter="bogus"/>`, &LogoutRequest{}},
		{"AuthnRequest", `<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &AuthnRequest{}},
		{"ArtifactResolve", `<ArtifactResolve xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &ArtifactResolve{}},
		{"ArtifactResponse", `<ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &ArtifactResponse{}},
		{"Response", `<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &Response{}},
		{"LogoutResponse", `<LogoutResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="bogus"/>`, &LogoutResponse{}},
		{"Assertion", `<Assertion xmlns="urn:oasis:names:tc:SAML:2.0:assertion" IssueInstant="bogus"/>`, &Assertion{}},
		{"SubjectConfirmationData", `<SubjectConfirmationData NotOnOrAfter="bogus"/>`, &SubjectConfirmationData{}},
		{"SubjectConfirmationDataNotBefore", `<SubjectConfirmationData NotBefore="bogus"/>`, &SubjectConfirmationData{}},
		{"ConditionsNotBefore", `<Conditions NotBefore="bogus"/>`, &Conditions{}},
		{"ConditionsNotOnOrAfter", `<Conditions NotOnOrAfter="bogus"/>`, &Conditions{}},
		{"AuthnStatement", `<AuthnStatement AuthnInstant="bogus"/>`, &AuthnStatement{}},
		{"AuthnStatementSessionNotOnOrAfter", `<AuthnStatement SessionNotOnOrAfter="bogus"/>`, &AuthnStatement{}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := xml.Unmarshal([]byte(tc.xml), tc.dst)
			assert.Check(t, is.ErrorContains(err, `cannot parse "bogus"`))
		})
	}
}

func TestSchemacovLogoutRequest(t *testing.T) {
	r := &LogoutRequest{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: schemacovTime,
		NotOnOrAfter: schemacovPtr(schemacovTime.Add(time.Minute)),
		Destination:  "https://idp.example.com/slo",
		Issuer:       &Issuer{Value: "https://sp.example.com/"},
		Signature:    schemacovSig(),
		NameID:       &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:transient", Value: "user"},
		SessionIndex: &SessionIndex{Value: "session-1"},
	}
	expected := `<samlp:LogoutRequest ` + schemacovNS + ` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z" NotOnOrAfter="2015-12-01T01:58:09.123Z" Destination="https://idp.example.com/slo">` +
		`<saml:Issuer>https://sp.example.com/</saml:Issuer>` +
		schemacovSigXML +
		`<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user</saml:NameID>` +
		`<samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">session-1</samlp:SessionIndex>` +
		`</samlp:LogoutRequest>`
	assert.Check(t, is.Equal(expected, schemacovString(t, r.Element())))

	// Bytes produces the same document.
	r.Signature = nil
	buf, err := r.Bytes()
	assert.NilError(t, err)
	assert.Check(t, is.Equal(`<samlp:LogoutRequest `+schemacovNS+` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z" NotOnOrAfter="2015-12-01T01:58:09.123Z" Destination="https://idp.example.com/slo">`+
		`<saml:Issuer>https://sp.example.com/</saml:Issuer>`+
		`<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient">user</saml:NameID>`+
		`<samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">session-1</samlp:SessionIndex>`+
		`</samlp:LogoutRequest>`, string(buf)))

	// Deflate is the raw-DEFLATE compression of Bytes.
	deflated, err := r.Deflate()
	assert.NilError(t, err)
	inflated, err := io.ReadAll(flate.NewReader(bytes.NewReader(deflated)))
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(buf, inflated))

	// The Element output unmarshals back into an equal struct.
	var got LogoutRequest
	assert.NilError(t, xml.Unmarshal(buf, &got))
	want := *r
	// The Alias-based UnmarshalXML does not populate the top-level XMLName.
	want.XMLName = xml.Name{}
	want.Issuer = &Issuer{XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"}, Value: "https://sp.example.com/"}
	assert.Check(t, is.DeepEqual(want, got))

	// MarshalXML: optional NotOnOrAfter omitted when nil, times use RelaxedTime.
	minimal := &LogoutRequest{ID: "id-2", Version: "2.0", IssueInstant: schemacovTime.Add(456 * time.Microsecond)}
	x, err := xml.Marshal(minimal)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(`<LogoutRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2015-12-01T01:57:09.123Z" ID="id-2" Version="2.0" Destination=""></LogoutRequest>`, string(x)))

	x, err = xml.Marshal(r)
	assert.NilError(t, err)
	var got2 LogoutRequest
	assert.NilError(t, xml.Unmarshal(x, &got2))
	assert.Check(t, is.DeepEqual(want, got2))
}

func TestSchemacovAuthnRequestElement(t *testing.T) {
	r := &AuthnRequest{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: schemacovTime,
		Destination:  "https://idp.example.com/sso",
		Consent:      "urn:oasis:names:tc:SAML:2.0:consent:obtained",
		Issuer:       &Issuer{Value: "https://sp.example.com/"},
		Signature:    schemacovSig(),
		Subject:      &Subject{NameID: &NameID{Value: "user"}},
		NameIDPolicy: &NameIDPolicy{
			Format:          schemacovPtr("urn:oasis:names:tc:SAML:2.0:nameid-format:transient"),
			SPNameQualifier: schemacovPtr("https://sp.example.com/"),
			AllowCreate:     schemacovPtr(true),
		},
		Conditions:                     &Conditions{NotOnOrAfter: schemacovTime},
		RequestedAuthnContext:          &RequestedAuthnContext{Comparison: "exact", AuthnContextClassRef: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"},
		ForceAuthn:                     schemacovPtr(true),
		IsPassive:                      schemacovPtr(false),
		AssertionConsumerServiceIndex:  "1",
		AssertionConsumerServiceURL:    "https://sp.example.com/acs",
		ProtocolBinding:                HTTPPostBinding,
		AttributeConsumingServiceIndex: "2",
		ProviderName:                   "Example SP",
	}
	expected := `<samlp:AuthnRequest ` + schemacovNS + ` ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z" Destination="https://idp.example.com/sso" Consent="urn:oasis:names:tc:SAML:2.0:consent:obtained"` +
		` ForceAuthn="true" IsPassive="false" AssertionConsumerServiceIndex="1" AssertionConsumerServiceURL="https://sp.example.com/acs" ProtocolBinding="urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST" AttributeConsumingServiceIndex="2" ProviderName="Example SP">` +
		`<saml:Issuer>https://sp.example.com/</saml:Issuer>` +
		schemacovSigXML +
		`<saml:Subject><saml:NameID>user</saml:NameID></saml:Subject>` +
		`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient" SPNameQualifier="https://sp.example.com/" AllowCreate="true"/>` +
		`<saml:Conditions NotOnOrAfter="2015-12-01T01:57:09.123Z"/>` +
		`<samlp:RequestedAuthnContext Comparison="exact"><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></samlp:RequestedAuthnContext>` +
		`</samlp:AuthnRequest>`
	assert.Check(t, is.Equal(expected, schemacovString(t, r.Element())))

	// Round trip (without the placeholder signature, which encoding/xml cannot
	// represent faithfully).
	r.Signature = nil
	var got AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, r.Element())), &got))
	assert.Check(t, is.Equal(r.ID, got.ID))
	assert.Check(t, got.IssueInstant.Equal(r.IssueInstant))
	assert.Check(t, is.Equal(r.Destination, got.Destination))
	assert.Check(t, is.Equal(r.Consent, got.Consent))
	assert.Check(t, is.Equal(r.Issuer.Value, got.Issuer.Value))
	assert.Check(t, is.Equal("user", got.Subject.NameID.Value))
	assert.Check(t, is.Equal(*r.NameIDPolicy.Format, *got.NameIDPolicy.Format))
	assert.Check(t, is.Equal(*r.NameIDPolicy.SPNameQualifier, *got.NameIDPolicy.SPNameQualifier))
	assert.Check(t, is.Equal(true, *got.NameIDPolicy.AllowCreate))
	assert.Check(t, got.Conditions.NotOnOrAfter.Equal(schemacovTime))
	assert.Check(t, is.DeepEqual(r.RequestedAuthnContext.AuthnContextClassRef, got.RequestedAuthnContext.AuthnContextClassRef))
	assert.Check(t, is.Equal(true, *got.ForceAuthn))
	assert.Check(t, is.Equal(false, *got.IsPassive))
	assert.Check(t, is.Equal(r.AssertionConsumerServiceIndex, got.AssertionConsumerServiceIndex))
	assert.Check(t, is.Equal(r.AssertionConsumerServiceURL, got.AssertionConsumerServiceURL))
	assert.Check(t, is.Equal(r.ProtocolBinding, got.ProtocolBinding))
	assert.Check(t, is.Equal(r.AttributeConsumingServiceIndex, got.AttributeConsumingServiceIndex))
	assert.Check(t, is.Equal(r.ProviderName, got.ProviderName))
}

func TestSchemacovIssuerAndNameIDElement(t *testing.T) {
	issuer := &Issuer{
		NameQualifier:   "nq",
		SPNameQualifier: "spnq",
		Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:entity",
		SPProvidedID:    "spid",
		Value:           "https://idp.example.com/",
	}
	x := schemacovString(t, issuer.Element())
	assert.Check(t, is.Equal(`<saml:Issuer NameQualifier="nq" SPNameQualifier="spnq" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:entity" SPProvidedID="spid">https://idp.example.com/</saml:Issuer>`, x))
	var gotIssuer Issuer
	assert.NilError(t, xml.Unmarshal(schemacovWrap(t, issuer.Element()), &struct {
		Issuer *Issuer `xml:"urn:oasis:names:tc:SAML:2.0:assertion Issuer"`
	}{&gotIssuer}))
	issuer.XMLName = xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"}
	assert.Check(t, is.DeepEqual(*issuer, gotIssuer))

	nameID := &NameID{
		NameQualifier:   "nq",
		SPNameQualifier: "spnq",
		Format:          "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent",
		SPProvidedID:    "spid",
		Value:           "user",
	}
	assert.Check(t, is.Equal(`<saml:NameID NameQualifier="nq" SPNameQualifier="spnq" Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent" SPProvidedID="spid">user</saml:NameID>`,
		schemacovString(t, nameID.Element())))
	var gotNameID NameID
	assert.NilError(t, xml.Unmarshal(schemacovWrap(t, nameID.Element()), &struct {
		NameID *NameID `xml:"urn:oasis:names:tc:SAML:2.0:assertion NameID"`
	}{&gotNameID}))
	assert.Check(t, is.DeepEqual(*nameID, gotNameID))

	// Empty optional attributes and value are omitted.
	assert.Check(t, is.Equal(`<saml:Issuer/>`, schemacovString(t, (&Issuer{}).Element())))
	assert.Check(t, is.Equal(`<saml:NameID/>`, schemacovString(t, (&NameID{}).Element())))
	assert.Check(t, is.Equal(`<samlp:SessionIndex xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`, schemacovString(t, (&SessionIndex{}).Element())))
}

func TestSchemacovArtifactResolve(t *testing.T) {
	r := &ArtifactResolve{
		ID:           "id-1",
		Version:      "2.0",
		IssueInstant: schemacovTime,
		Issuer:       &Issuer{Value: "https://sp.example.com/"},
		Signature:    schemacovSig(),
		Artifact:     "AAQAAA==",
	}
	// Signature must precede Artifact (ADFS requirement, see issue #535).
	assert.Check(t, is.Equal(`<samlp:ArtifactResolve `+schemacovNS+` xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z">`+
		`<saml:Issuer>https://sp.example.com/</saml:Issuer>`+schemacovSigXML+`<samlp:Artifact>AAQAAA==</samlp:Artifact></samlp:ArtifactResolve>`,
		schemacovString(t, r.Element())))

	r.Signature = nil
	var got ArtifactResolve
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, r.Element())), &got))
	assert.Check(t, is.Equal("AAQAAA==", got.Artifact))
	assert.Check(t, got.IssueInstant.Equal(schemacovTime))
	assert.Check(t, is.Equal("https://sp.example.com/", got.Issuer.Value))
}

func schemacovStatus() Status {
	return Status{
		StatusCode: StatusCode{
			Value:      StatusRequester,
			StatusCode: &StatusCode{Value: StatusRequestDenied},
		},
		StatusMessage: &StatusMessage{Value: "denied"},
		StatusDetail:  &StatusDetail{Children: []*etree.Element{etree.NewElement("detail")}},
	}
}

const schemacovStatusXML = `<samlp:Status>` +
	`<samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Requester"><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:RequestDenied"/></samlp:StatusCode>` +
	`<samlp:StatusMessage>denied</samlp:StatusMessage>` +
	`<samlp:StatusDetail><detail/></samlp:StatusDetail>` +
	`</samlp:Status>`

func TestSchemacovStatusElement(t *testing.T) {
	s := schemacovStatus()
	assert.Check(t, is.Equal(schemacovStatusXML, schemacovString(t, s.Element())))

	assert.Check(t, is.Equal(`<samlp:StatusMessage>m</samlp:StatusMessage>`, schemacovString(t, StatusMessage{Value: "m"}.Element())))
	assert.Check(t, is.Equal(`<samlp:StatusDetail/>`, schemacovString(t, StatusDetail{}.Element())))
	assert.Check(t, is.Equal(`<samlp:StatusDetail><a/><b/></samlp:StatusDetail>`,
		schemacovString(t, StatusDetail{Children: []*etree.Element{etree.NewElement("a"), etree.NewElement("b")}}.Element())))

	// Round trip of StatusCode/StatusMessage.
	var got Status
	assert.NilError(t, xml.Unmarshal(schemacovWrap(t, s.Element()), &struct {
		Status *Status `xml:"urn:oasis:names:tc:SAML:2.0:protocol Status"`
	}{&got}))
	assert.Check(t, is.Equal(StatusRequester, got.StatusCode.Value))
	assert.Assert(t, got.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(StatusRequestDenied, got.StatusCode.StatusCode.Value))
	assert.Assert(t, got.StatusMessage != nil)
	assert.Check(t, is.Equal("denied", got.StatusMessage.Value))
	assert.Check(t, got.StatusDetail != nil)
}

func TestSchemacovArtifactResponse(t *testing.T) {
	r := &ArtifactResponse{
		ID:           "id-1",
		InResponseTo: "req-1",
		Version:      "2.0",
		IssueInstant: schemacovTime,
		Issuer:       &Issuer{Value: "https://idp.example.com/"},
		Signature:    schemacovSig(),
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		Response: Response{
			ID:           "id-2",
			Version:      "2.0",
			IssueInstant: schemacovTime,
			Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
		},
	}
	assert.Check(t, is.Equal(`<samlp:ArtifactResponse `+schemacovNS+` xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id-1" InResponseTo="req-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z">`+
		`<saml:Issuer>https://idp.example.com/</saml:Issuer>`+schemacovSigXML+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`+
		`<samlp:Response `+schemacovNS+` xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id-2" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z">`+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status></samlp:Response>`+
		`</samlp:ArtifactResponse>`,
		schemacovString(t, r.Element())))

	r.Signature = nil
	var got ArtifactResponse
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, r.Element())), &got))
	assert.Check(t, is.Equal("req-1", got.InResponseTo))
	assert.Check(t, got.IssueInstant.Equal(schemacovTime))
	assert.Check(t, is.Equal(StatusSuccess, got.Status.StatusCode.Value))
	assert.Check(t, is.Equal("id-2", got.Response.ID))
	assert.Check(t, got.Response.IssueInstant.Equal(schemacovTime))

	// MarshalXML uses RelaxedTime (UTC, millisecond rounding) for IssueInstant
	// and the result can be unmarshalled again.
	r.IssueInstant = schemacovTime.Add(456 * time.Microsecond).In(time.FixedZone("x", 3600))
	x, err := xml.Marshal(r)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(x), `<ArtifactResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2015-12-01T01:57:09.123Z" ID="id-1" InResponseTo="req-1" Version="2.0">`))
	var got2 ArtifactResponse
	assert.NilError(t, xml.Unmarshal(x, &got2))
	assert.Check(t, got2.IssueInstant.Equal(schemacovTime))
	assert.Check(t, is.Equal("id-2", got2.Response.ID))
	assert.Check(t, is.Equal("https://idp.example.com/", got2.Issuer.Value))
}

func TestSchemacovResponse(t *testing.T) {
	encrypted := etree.NewElement("saml:EncryptedAssertion")
	r := &Response{
		ID:                 "id-1",
		InResponseTo:       "req-1",
		Version:            "2.0",
		IssueInstant:       schemacovTime,
		Destination:        "https://sp.example.com/acs",
		Consent:            "urn:oasis:names:tc:SAML:2.0:consent:unspecified",
		Issuer:             &Issuer{Value: "https://idp.example.com/"},
		Signature:          schemacovSig(),
		Status:             Status{StatusCode: StatusCode{Value: StatusSuccess}},
		EncryptedAssertion: encrypted,
		Assertion: &Assertion{
			ID:           "a-1",
			IssueInstant: schemacovTime,
			Issuer:       Issuer{Value: "https://idp.example.com/"},
		},
	}
	assert.Check(t, is.Equal(`<samlp:Response `+schemacovNS+` xmlns:xs="http://www.w3.org/2001/XMLSchema" ID="id-1" InResponseTo="req-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z" Destination="https://sp.example.com/acs" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified">`+
		`<saml:Issuer>https://idp.example.com/</saml:Issuer>`+schemacovSigXML+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`+
		`<saml:EncryptedAssertion/>`+
		`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-1" IssueInstant="2015-12-01T01:57:09.123Z" Version="2.0"><saml:Issuer>https://idp.example.com/</saml:Issuer></saml:Assertion>`+
		`</samlp:Response>`,
		schemacovString(t, r.Element())))

	r.Signature = nil
	r.EncryptedAssertion = nil
	var got Response
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, r.Element())), &got))
	assert.Check(t, is.Equal("req-1", got.InResponseTo))
	assert.Check(t, is.Equal(r.Destination, got.Destination))
	assert.Check(t, is.Equal(r.Consent, got.Consent))
	assert.Check(t, got.IssueInstant.Equal(schemacovTime))
	assert.Assert(t, got.Assertion != nil)
	assert.Check(t, is.Equal("a-1", got.Assertion.ID))
	assert.Check(t, is.Equal("2.0", got.Assertion.Version))
	assert.Check(t, got.Assertion.IssueInstant.Equal(schemacovTime))

	// MarshalXML
	r.Assertion = nil
	x, err := xml.Marshal(r)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(`<Response xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2015-12-01T01:57:09.123Z" ID="id-1" InResponseTo="req-1" Version="2.0" Destination="https://sp.example.com/acs" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified">`+
		`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion" NameQualifier="" SPNameQualifier="" Format="" SPProvidedID="">https://idp.example.com/</Issuer>`+
		`<Status xmlns="urn:oasis:names:tc:SAML:2.0:protocol"><StatusCode xmlns="urn:oasis:names:tc:SAML:2.0:protocol" Value="urn:oasis:names:tc:SAML:2.0:status:Success"></StatusCode></Status>`+
		`</Response>`, string(x)))
	var got2 Response
	assert.NilError(t, xml.Unmarshal(x, &got2))
	assert.Check(t, got2.IssueInstant.Equal(schemacovTime))
	assert.Check(t, is.Equal(StatusSuccess, got2.Status.StatusCode.Value))
}

func TestSchemacovAssertionElement(t *testing.T) {
	a := &Assertion{
		ID:           "a-1",
		IssueInstant: schemacovTime,
		Version:      "ignored", // Element always emits Version="2.0"
		Issuer:       Issuer{Value: "https://idp.example.com/"},
		Signature:    schemacovSig(),
		Subject: &Subject{
			NameID: &NameID{Value: "user"},
			SubjectConfirmations: []SubjectConfirmation{{
				Method: "urn:oasis:names:tc:SAML:2.0:cm:bearer",
				NameID: &NameID{Value: "user"},
				SubjectConfirmationData: &SubjectConfirmationData{
					NotBefore:    schemacovTime,
					NotOnOrAfter: schemacovTime.Add(time.Minute),
					Recipient:    "https://sp.example.com/acs",
					InResponseTo: "req-1",
					Address:      "10.0.0.1",
				},
			}},
		},
		Conditions: &Conditions{
			NotBefore:            schemacovTime,
			NotOnOrAfter:         schemacovTime.Add(time.Minute),
			AudienceRestrictions: []AudienceRestriction{{Audience: Audience{Value: "https://sp.example.com/"}}},
			OneTimeUse:           &OneTimeUse{},
			ProxyRestriction: &ProxyRestriction{
				Count:     schemacovPtr(2),
				Audiences: []Audience{{Value: "https://a.example.com/"}, {Value: "https://b.example.com/"}},
			},
		},
		AuthnStatements: []AuthnStatement{{
			AuthnInstant:        schemacovTime,
			SessionIndex:        "s-1",
			SessionNotOnOrAfter: schemacovPtr(schemacovTime.Add(time.Hour)),
			SubjectLocality:     &SubjectLocality{Address: "10.0.0.1", DNSName: "client.example.com"},
			AuthnContext:        AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"}},
		}},
		AttributeStatements: []AttributeStatement{{
			Attributes: []Attribute{{
				Name:   "member",
				Values: []AttributeValue{{NameID: &NameID{Value: "group"}}},
			}},
		}},
	}
	assert.Check(t, is.Equal(`<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="a-1" IssueInstant="2015-12-01T01:57:09.123Z" Version="2.0">`+
		`<saml:Issuer>https://idp.example.com/</saml:Issuer>`+
		schemacovSigXML+
		`<saml:Subject><saml:NameID>user</saml:NameID>`+
		`<saml:SubjectConfirmation Method="urn:oasis:names:tc:SAML:2.0:cm:bearer"><saml:NameID>user</saml:NameID>`+
		`<saml:SubjectConfirmationData Address="10.0.0.1" InResponseTo="req-1" NotBefore="2015-12-01T01:57:09.123Z" NotOnOrAfter="2015-12-01T01:58:09.123Z" Recipient="https://sp.example.com/acs"/>`+
		`</saml:SubjectConfirmation></saml:Subject>`+
		`<saml:Conditions NotBefore="2015-12-01T01:57:09.123Z" NotOnOrAfter="2015-12-01T01:58:09.123Z">`+
		`<saml:AudienceRestriction><saml:Audience>https://sp.example.com/</saml:Audience></saml:AudienceRestriction>`+
		`<saml:OneTimeUse/>`+
		`<saml:ProxyRestriction Count="2"><saml:Audience>https://a.example.com/</saml:Audience><saml:Audience>https://b.example.com/</saml:Audience></saml:ProxyRestriction>`+
		`</saml:Conditions>`+
		`<saml:AuthnStatement AuthnInstant="2015-12-01T01:57:09.123Z" SessionIndex="s-1" SessionNotOnOrAfter="2015-12-01T02:57:09.123Z">`+
		`<saml:SubjectLocality Address="10.0.0.1" DNSName="client.example.com"/>`+
		`<saml:AuthnContext><saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef></saml:AuthnContext>`+
		`</saml:AuthnStatement>`+
		`<saml:AttributeStatement><saml:Attribute Name="member"><saml:AttributeValue><saml:NameID>group</saml:NameID></saml:AttributeValue></saml:Attribute></saml:AttributeStatement>`+
		`</saml:Assertion>`,
		schemacovString(t, a.Element())))

	// Round trip through UnmarshalXML.
	a.Signature = nil
	var got Assertion
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, a.Element())), &got))
	want := *a
	// The Alias-based UnmarshalXML does not populate the top-level XMLName.
	want.XMLName = xml.Name{}
	want.Version = "2.0"
	want.Issuer.XMLName = xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"}
	want.Subject.XMLName = xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Subject"}
	assert.Check(t, is.DeepEqual(want, got))
}

func TestSchemacovAssertionElementPanicsOnInvalidNamespace(t *testing.T) {
	// A child that re-declares the reserved "xmlns" prefix makes exclusive
	// canonicalization fail, which Element reports by panicking.
	sig := etree.NewElement("ds:Signature")
	sig.CreateAttr("xmlns:xmlns", "urn:bogus")
	a := &Assertion{ID: "a-1", IssueInstant: schemacovTime, Signature: sig}
	defer func() {
		r := recover()
		assert.Check(t, r != nil)
		err, ok := r.(error)
		assert.Assert(t, ok)
		assert.Check(t, is.ErrorContains(err, "reserved namespace"))
	}()
	a.Element()
	t.Fatal("expected panic")
}

func TestSchemacovConditionsElements(t *testing.T) {
	assert.Check(t, is.Equal(`<saml:Conditions/>`, schemacovString(t, (&Conditions{}).Element())))
	assert.Check(t, is.Equal(`<saml:OneTimeUse/>`, schemacovString(t, (&OneTimeUse{}).Element())))
	assert.Check(t, is.Equal(`<saml:ProxyRestriction/>`, schemacovString(t, (&ProxyRestriction{}).Element())))
	assert.Check(t, is.Equal(`<saml:ProxyRestriction Count="0"/>`, schemacovString(t, (&ProxyRestriction{Count: schemacovPtr(0)}).Element())))

	pr := &ProxyRestriction{Count: schemacovPtr(3), Audiences: []Audience{{Value: "x"}}}
	var got ProxyRestriction
	assert.NilError(t, xml.Unmarshal(schemacovWrap(t, pr.Element()), &struct {
		PR *ProxyRestriction `xml:"urn:oasis:names:tc:SAML:2.0:assertion ProxyRestriction"`
	}{&got}))
	assert.Check(t, is.DeepEqual(*pr, got))

	assert.Check(t, is.Equal(`<saml:SubjectConfirmationData/>`, schemacovString(t, (&SubjectConfirmationData{}).Element())))
	assert.Check(t, is.Equal(`<saml:SubjectConfirmation Method=""/>`, schemacovString(t, (&SubjectConfirmation{}).Element())))
	assert.Check(t, is.Equal(`<saml:SubjectLocality/>`, schemacovString(t, (&SubjectLocality{}).Element())))
	assert.Check(t, is.Equal(`<saml:AuthnContext/>`, schemacovString(t, (&AuthnContext{}).Element())))
}

func TestSchemacovAttributeValueElement(t *testing.T) {
	// xsi:type is optional and is omitted when Type is empty: an empty
	// xsi:type is not a valid QName.
	av := &AttributeValue{NameID: &NameID{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent", Value: "group"}}
	assert.Check(t, is.Equal(`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema">`+
		`<saml:NameID Format="urn:oasis:names:tc:SAML:2.0:nameid-format:persistent">group</saml:NameID></saml:AttributeValue>`,
		schemacovString(t, av.Element())))

	var got AttributeValue
	assert.NilError(t, xml.Unmarshal(schemacovWrap(t, av.Element()), &struct {
		AV *AttributeValue `xml:"urn:oasis:names:tc:SAML:2.0:assertion AttributeValue"`
	}{&got}))
	assert.Check(t, is.DeepEqual(*av, got))

	typed := &AttributeValue{Type: "xs:string", Value: "v"}
	assert.Check(t, is.Equal(`<saml:AttributeValue xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xs="http://www.w3.org/2001/XMLSchema" xsi:type="xs:string">v</saml:AttributeValue>`,
		schemacovString(t, typed.Element())))
}

func TestSchemacovLogoutResponse(t *testing.T) {
	r := &LogoutResponse{
		ID:           "id-1",
		InResponseTo: "req-1",
		Version:      "2.0",
		IssueInstant: schemacovTime,
		Destination:  "https://sp.example.com/slo",
		Consent:      "urn:oasis:names:tc:SAML:2.0:consent:unspecified",
		Issuer:       &Issuer{Value: "https://idp.example.com/"},
		Signature:    schemacovSig(),
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}, StatusMessage: &StatusMessage{Value: "ok"}},
	}
	assert.Check(t, is.Equal(`<samlp:LogoutResponse `+schemacovNS+` ID="id-1" InResponseTo="req-1" Version="2.0" IssueInstant="2015-12-01T01:57:09.123Z" Destination="https://sp.example.com/slo" Consent="urn:oasis:names:tc:SAML:2.0:consent:unspecified">`+
		`<saml:Issuer>https://idp.example.com/</saml:Issuer>`+schemacovSigXML+
		`<samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/><samlp:StatusMessage>ok</samlp:StatusMessage></samlp:Status>`+
		`</samlp:LogoutResponse>`,
		schemacovString(t, r.Element())))

	r.Signature = nil
	want := *r
	// The Alias-based UnmarshalXML does not populate the top-level XMLName.
	want.XMLName = xml.Name{}
	want.Issuer = &Issuer{XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:assertion", Local: "Issuer"}, Value: "https://idp.example.com/"}
	want.Status = Status{
		XMLName:       xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:protocol", Local: "Status"},
		StatusCode:    StatusCode{XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:protocol", Local: "StatusCode"}, Value: StatusSuccess},
		StatusMessage: &StatusMessage{XMLName: xml.Name{Space: "urn:oasis:names:tc:SAML:2.0:protocol", Local: "StatusMessage"}, Value: "ok"},
	}

	// Element -> UnmarshalXML
	var got LogoutResponse
	assert.NilError(t, xml.Unmarshal([]byte(schemacovString(t, r.Element())), &got))
	assert.Check(t, is.DeepEqual(want, got))

	// MarshalXML -> UnmarshalXML
	x, err := xml.Marshal(r)
	assert.NilError(t, err)
	assert.Check(t, is.Contains(string(x), `<LogoutResponse xmlns="urn:oasis:names:tc:SAML:2.0:protocol" IssueInstant="2015-12-01T01:57:09.123Z" ID="id-1" InResponseTo="req-1" Version="2.0"`))
	var got2 LogoutResponse
	assert.NilError(t, xml.Unmarshal(x, &got2))
	assert.Check(t, is.DeepEqual(want, got2))
}
