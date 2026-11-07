package saml

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"errors"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const (
	aqLocation        = "https://idp.example.com/saml/aa"
	aqMailOID         = "urn:oid:0.9.2342.19200300.100.1.3"
	aqURINameFormat   = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"
	aqSenderVouches   = "urn:oasis:names:tc:SAML:2.0:cm:sender-vouches"
	aqStatusPrincipal = "urn:oasis:names:tc:SAML:2.0:status:UnknownPrincipal"
)

var aqNameID = NameID{Format: string(PersistentNameIDFormat), Value: "alice-persistent-id"}

// aqSetup returns the spcovSetup environment with an IdP that also
// publishes an AttributeAuthorityDescriptor.
func aqSetup(t *testing.T) *spcovEnv {
	t.Helper()
	e := spcovSetup(t)
	e.sp.IDPMetadata.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{{
		AttributeServices: []Endpoint{{Binding: SOAPBinding, Location: aqLocation}},
	}}
	return e
}

func (e *spcovEnv) aqQuery(t *testing.T) *AttributeQuery {
	t.Helper()
	query, err := e.sp.MakeAttributeQuery(aqNameID, Attribute{Name: aqMailOID, NameFormat: aqURINameFormat})
	assert.NilError(t, err)
	return query
}

// aqAssertion is what an attribute authority returns for query: a
// sender-vouches assertion about the queried subject, with no
// SubjectConfirmationData.
func (e *spcovEnv) aqAssertion(query *AttributeQuery) *Assertion {
	assertion := e.assertion()
	nameID := *query.Subject.NameID
	assertion.Subject = &Subject{
		NameID:               &nameID,
		SubjectConfirmations: []SubjectConfirmation{{Method: aqSenderVouches}},
	}
	assertion.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{{
		FriendlyName: "mail",
		Name:         aqMailOID,
		NameFormat:   aqURINameFormat,
		Values:       []AttributeValue{{Type: "xs:string", Value: "alice@example.com"}},
	}}}}
	return assertion
}

type aqOptions struct {
	signResponse  bool
	signAssertion bool
	encrypt       bool
	noAssertion   bool
	response      func(*Response)
	assertion     func(*Assertion)
	// sign, if set, signs instead of the IdP.
	sign func(*etree.Element) *etree.Element
}

// aqResponseEl returns the samlp:Response the attribute authority sends for
// query.
func (e *spcovEnv) aqResponseEl(t *testing.T, query *AttributeQuery, o aqOptions) *etree.Element {
	t.Helper()
	sign := o.sign
	if sign == nil {
		sign = func(el *etree.Element) *etree.Element { return e.idpSign(t, el) }
	}
	response := e.response()
	response.InResponseTo = query.ID
	response.Destination = ""
	if o.response != nil {
		o.response(response)
	}
	el := response.Element()
	if !o.noAssertion {
		assertion := e.aqAssertion(query)
		if o.assertion != nil {
			o.assertion(assertion)
		}
		assertionEl := assertion.Element()
		if o.signAssertion {
			assertionEl = sign(assertionEl)
		}
		if o.encrypt {
			assertionEl = e.encryptedAssertion(t, spcovSerialize(t, assertionEl))
		}
		el.AddChild(assertionEl)
	}
	if o.signResponse {
		el = sign(el)
	}
	return el
}

func (e *spcovEnv) aqSOAP(t *testing.T, query *AttributeQuery, o aqOptions) []byte {
	t.Helper()
	return spcovSerialize(t, spcovSOAPEnvelope(e.aqResponseEl(t, query, o)))
}

// aqVerify verifies the enveloped signature of el with the SP certificate.
func aqVerify(t *testing.T, e *spcovEnv, el *etree.Element) {
	t.Helper()
	buf, err := elementToBytes(el)
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	ctx := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{e.sp.Certificate}})
	ctx.IdAttribute = "ID"
	ctx.Clock = dsig.NewFakeClockAt(spcovNow)
	_, err = ctx.Validate(doc.Root())
	assert.NilError(t, err)
}

func TestMakeAttributeQuery(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)

	assert.Check(t, strings.HasPrefix(query.ID, "id-"))
	assert.Check(t, is.Equal(query.Version, "2.0"))
	assert.Check(t, query.IssueInstant.Equal(spcovNow))
	assert.Check(t, is.Equal(query.Destination, aqLocation))
	assert.Check(t, is.Equal(query.Issuer.Value, "https://sp.example.com/saml/metadata"))
	assert.Check(t, is.Equal(query.Issuer.Format, "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"))
	assert.Check(t, is.DeepEqual(*query.Subject.NameID, aqNameID))
	assert.Check(t, is.Len(query.Attributes, 1))

	// Signed with SHA-256 by default, although SignatureMethod is not set.
	assert.Assert(t, query.Signature != nil)
	method := query.Signature.FindElement("./SignedInfo/SignatureMethod")
	assert.Assert(t, method != nil)
	assert.Check(t, is.Equal(method.SelectAttrValue("Algorithm", ""), dsig.RSASHA256SignatureMethod))
	aqVerify(t, e, query.Element())

	// The signature still verifies in the SOAP envelope sent on the wire.
	buf, err := elementToBytes(query.SoapRequest())
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	body, err := findOneChild(doc.Root(), soapEnvelopeNamespace, "Body")
	assert.NilError(t, err)
	queryEl, err := findOneChild(body, "urn:oasis:names:tc:SAML:2.0:protocol", "AttributeQuery")
	assert.NilError(t, err)
	aqVerify(t, e, queryEl)
	children := queryEl.ChildElements()
	assert.Assert(t, is.Len(children, 4))
	for i, tag := range []string{"Issuer", "Signature", "Subject", "Attribute"} {
		assert.Check(t, is.Equal(children[i].Tag, tag))
	}
}

func TestMakeAttributeQuerySignatureMethod(t *testing.T) {
	e := aqSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA512SignatureMethod
	query := e.aqQuery(t)
	method := query.Signature.FindElement("./SignedInfo/SignatureMethod")
	assert.Assert(t, method != nil)
	assert.Check(t, is.Equal(method.SelectAttrValue("Algorithm", ""), dsig.RSASHA512SignatureMethod))

	// Signing again replaces the signature rather than adding a second one.
	assert.NilError(t, e.sp.SignAttributeQuery(query))
	assert.Check(t, is.Len(query.Element().SelectElements("Signature"), 1))
	aqVerify(t, e, query.Element())
}

func TestMakeAttributeQueryWithoutKeyIsUnsigned(t *testing.T) {
	e := aqSetup(t)
	e.sp.Key = nil
	query := e.aqQuery(t)
	assert.Check(t, query.Signature == nil)
}

func TestMakeAttributeQueryErrors(t *testing.T) {
	t.Run("no AttributeAuthorityDescriptor", func(t *testing.T) {
		e := spcovSetup(t)
		_, err := e.sp.MakeAttributeQuery(aqNameID)
		assert.Check(t, errors.Is(err, ErrNoAttributeService), "%v", err)
		_, err = e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.Check(t, errors.Is(err, ErrNoAttributeService), "%v", err)
	})
	t.Run("no SOAP AttributeService", func(t *testing.T) {
		e := aqSetup(t)
		e.sp.IDPMetadata.AttributeAuthorityDescriptors[0].AttributeServices[0].Binding = HTTPPostBinding
		_, err := e.sp.MakeAttributeQuery(aqNameID)
		assert.Check(t, errors.Is(err, ErrNoAttributeService), "%v", err)
	})
	t.Run("no IDPMetadata", func(t *testing.T) {
		e := aqSetup(t)
		e.sp.IDPMetadata = nil
		_, err := e.sp.MakeAttributeQuery(aqNameID)
		assert.Check(t, is.ErrorContains(err, "IDPMetadata is not set"))
	})
	t.Run("empty NameID", func(t *testing.T) {
		e := aqSetup(t)
		_, err := e.sp.MakeAttributeQuery(NameID{Format: string(PersistentNameIDFormat)})
		assert.Check(t, is.ErrorContains(err, "the NameID is empty"))
	})
	t.Run("attribute requested twice", func(t *testing.T) {
		e := aqSetup(t)
		_, err := e.sp.MakeAttributeQuery(aqNameID, Attribute{Name: "mail"}, Attribute{Name: "mail"})
		assert.Check(t, is.ErrorContains(err, `attribute "mail" is requested more than once`))
		// The same Name with another NameFormat is a different attribute.
		_, err = e.sp.MakeAttributeQuery(aqNameID, Attribute{Name: "mail"}, Attribute{Name: "mail", NameFormat: aqURINameFormat})
		assert.Check(t, err)
	})
	t.Run("attribute without Name", func(t *testing.T) {
		e := aqSetup(t)
		_, err := e.sp.MakeAttributeQuery(aqNameID, Attribute{FriendlyName: "mail"})
		assert.Check(t, is.ErrorContains(err, "has no Name"))
	})
	t.Run("signing fails", func(t *testing.T) {
		e := aqSetup(t)
		e.sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		_, err := e.sp.MakeAttributeQuery(aqNameID)
		assert.Check(t, is.ErrorContains(err, "requires an ECDSA key"))
	})
}

func TestParseXMLAttributeQueryResponseAccepts(t *testing.T) {
	testCases := []struct {
		name string
		o    aqOptions
	}{
		{"signed response", aqOptions{signResponse: true}},
		{"signed assertion", aqOptions{signAssertion: true}},
		{"signed response and assertion", aqOptions{signResponse: true, signAssertion: true}},
		{"encrypted signed assertion", aqOptions{signAssertion: true, encrypt: true}},
		{"signed response, encrypted assertion", aqOptions{signResponse: true, encrypt: true}},
		{"no SubjectConfirmation", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations = nil
		}}},
		{"SubjectConfirmationData for the query", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &SubjectConfirmationData{
				NotOnOrAfter: spcovNow.Add(time.Minute),
			}
		}}},
		{"Destination is the SP entity ID", aqOptions{signResponse: true, response: func(r *Response) {
			r.Destination = "https://sp.example.com/saml/metadata"
		}}},
		{"unsigned response without Issuer", aqOptions{signAssertion: true, response: func(r *Response) {
			r.Issuer = nil
		}}},
		{"NameID spells out the default qualifiers", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.NameID.NameQualifier = spcovIDPEntityID
			a.Subject.NameID.SPNameQualifier = "https://sp.example.com/saml/metadata"
		}}},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := aqSetup(t)
			query := e.aqQuery(t)
			result, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, tc.o), query)
			assert.NilError(t, err)
			assert.Assert(t, is.Len(result.Assertions, 1))
			assert.Check(t, is.Equal(result.Assertions[0].ID, "id-assertion"))
			assert.Assert(t, is.Len(result.Attributes, 1))
			assert.Check(t, is.Equal(result.Attributes[0].Name, aqMailOID))
			assert.Check(t, is.Equal(result.Attributes[0].FriendlyName, "mail"))
			assert.Check(t, is.Equal(result.Attributes[0].Values[0].Value, "alice@example.com"))
		})
	}
}

func TestParseXMLAttributeQueryResponseSignedWithoutAssertion(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)
	result, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, noAssertion: true}), query)
	assert.NilError(t, err)
	assert.Check(t, is.Len(result.Assertions, 0))
	assert.Check(t, is.Len(result.Attributes, 0))
}

func TestParseXMLAttributeQueryResponseRejects(t *testing.T) {
	otherNameID := func(a *Assertion) { a.Subject.NameID.Value = "bob-persistent-id" }
	testCases := []struct {
		name string
		o    aqOptions
		err  string
	}{
		{"unsigned response and assertion", aqOptions{},
			"neither the Response nor its Assertion is signed"},
		{"unsigned response without assertion", aqOptions{noAssertion: true},
			"the Response is not signed and has no Assertion"},
		{"wrong InResponseTo", aqOptions{signResponse: true, response: func(r *Response) { r.InResponseTo = "id-other" }},
			"does not match the attribute query ID"},
		{"no InResponseTo", aqOptions{signResponse: true, response: func(r *Response) { r.InResponseTo = "" }},
			"does not match the attribute query ID"},
		{"wrong response Issuer", aqOptions{signResponse: true, response: func(r *Response) { r.Issuer.Value = "https://evil.example.com" }},
			"response Issuer does not match the IDP metadata"},
		{"signed response without Issuer", aqOptions{signResponse: true, response: func(r *Response) { r.Issuer = nil }},
			"the signed Response has no Issuer"},
		{"wrong assertion Issuer", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Issuer.Value = "https://evil.example.com" }},
			`issuer is not "https://idp.example.com/metadata"`},
		{"expired response", aqOptions{signResponse: true, response: func(r *Response) { r.IssueInstant = spcovNow.Add(-time.Hour) }},
			"response IssueInstant expired"},
		{"Destination of another party", aqOptions{signResponse: true, response: func(r *Response) { r.Destination = aqLocation }},
			"is not this service provider"},
		{"Destination of the ACS", aqOptions{signResponse: true, response: func(r *Response) { r.Destination = "https://sp.example.com/saml/acs" }},
			"is not this service provider"},
		{"another NameID", aqOptions{signResponse: true, assertion: otherNameID},
			`assertion Subject NameID "bob-persistent-id" does not match the queried NameID "alice-persistent-id"`},
		{"another NameID format", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Subject.NameID.Format = string(TransientNameIDFormat) }},
			"does not match the queried NameID"},
		{"another NameQualifier", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Subject.NameID.NameQualifier = "https://other-idp.example.com" }},
			"does not match the queried NameID"},
		{"another SPNameQualifier", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Subject.NameID.SPNameQualifier = "https://other-sp.example.com" }},
			"does not match the queried NameID"},
		{"no Subject", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Subject = nil }},
			"assertion has no Subject NameID"},
		{"no Conditions", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Conditions = nil }},
			"assertion has no Conditions"},
		{"audience of another SP", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Conditions.AudienceRestrictions[0].Audience.Value = "https://other-sp.example.com"
		}}, `assertion Conditions AudienceRestriction does not contain "https://sp.example.com/saml/metadata"`},
		{"no AudienceRestriction", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.Conditions.AudienceRestrictions = nil }},
			"assertion Conditions has no AudienceRestriction"},
		{"expired Conditions", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Conditions.NotOnOrAfter = spcovNow.Add(-MaxClockSkew - time.Second)
		}}, "assertion Conditions is expired"},
		{"Conditions not yet valid", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Conditions.NotBefore = spcovNow.Add(MaxClockSkew + time.Second)
		}}, "assertion Conditions is not yet valid"},
		{"expired assertion", aqOptions{signResponse: true, assertion: func(a *Assertion) { a.IssueInstant = spcovNow.Add(-time.Hour) }},
			"expired on"},
		{"SubjectConfirmationData for another request", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &SubjectConfirmationData{InResponseTo: "id-other"}
		}}, `SubjectConfirmationData InResponseTo "id-other" is not the attribute query ID`},
		{"expired SubjectConfirmationData", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &SubjectConfirmationData{
				NotOnOrAfter: spcovNow.Add(-MaxClockSkew - time.Second),
			}
		}}, "assertion SubjectConfirmationData is expired"},
		{"SubjectConfirmationData not yet valid", aqOptions{signResponse: true, assertion: func(a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &SubjectConfirmationData{
				NotBefore: spcovNow.Add(MaxClockSkew + time.Second),
			}
		}}, "assertion SubjectConfirmationData is not yet valid"},
		{"Requester status", aqOptions{signResponse: true, response: func(r *Response) {
			r.Status.StatusCode = StatusCode{Value: StatusRequester}
		}}, StatusRequester},
		{"encrypted unsigned assertion in unsigned response", aqOptions{encrypt: true},
			"neither the Response nor its Assertion is signed"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			e := aqSetup(t)
			query := e.aqQuery(t)
			_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, tc.o), query)
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), tc.err))
		})
	}
}

func TestParseXMLAttributeQueryResponseBadStatus(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)
	buf := e.aqSOAP(t, query, aqOptions{noAssertion: true, response: func(r *Response) {
		r.Status = Status{
			StatusCode:    StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: aqStatusPrincipal}},
			StatusMessage: &StatusMessage{Value: "no such user"},
		}
	}})
	_, err := e.sp.ParseXMLAttributeQueryResponse(buf, query)
	privateErr := spcovPrivateErr(t, err)
	var badStatus ErrBadStatus
	assert.Assert(t, errors.As(privateErr, &badStatus), "%v", privateErr)
	assert.Check(t, is.Equal(badStatus.Status, StatusResponder))
	assert.Check(t, is.Error(privateErr, StatusResponder+" ("+aqStatusPrincipal+"): no such user"))
}

func TestParseXMLAttributeQueryResponseSignatures(t *testing.T) {
	otherKey, otherCert := aqKeyPair(t)
	otherSign := func(el *etree.Element) *etree.Element {
		return spcovSign(t, otherKey, otherCert, el)
	}
	t.Run("response signed by another key", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, sign: otherSign}), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
	})
	t.Run("assertion signed by another key", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signAssertion: true, sign: otherSign}), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Assertion"))
	})
	t.Run("signed response modified after signing", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		el := e.aqResponseEl(t, query, aqOptions{signResponse: true})
		value := el.FindElement("//AttributeValue")
		assert.Assert(t, value != nil)
		value.SetText("mallory@example.com")
		_, err := e.sp.ParseXMLAttributeQueryResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
	})
	t.Run("a second, unsigned assertion in a response with a signed one", func(t *testing.T) {
		e := aqSetup(t)
		query := e.aqQuery(t)
		el := e.aqResponseEl(t, query, aqOptions{signAssertion: true})
		extra := e.aqAssertion(query)
		extra.ID = "id-injected"
		el.AddChild(extra.Element())
		_, err := e.sp.ParseXMLAttributeQueryResponse(spcovSerialize(t, spcovSOAPEnvelope(el)), query)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "neither the Response nor its Assertion is signed"))
	})
}

// aqKeyPair returns a new RSA key and a certificate for it that is valid at
// spcovNow.
func aqKeyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	assert.NilError(t, err)
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "aa.idp.example.com"},
		NotBefore:    spcovNow.Add(-time.Hour),
		NotAfter:     spcovNow.Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, key.Public(), key)
	assert.NilError(t, err)
	cert, err := x509.ParseCertificate(der)
	assert.NilError(t, err)
	return key, cert
}

// An attribute authority that publishes its own signing key is trusted with
// that key only; the IdP SSO key is a fallback for one that publishes none.
func TestParseXMLAttributeQueryResponseAttributeAuthorityKey(t *testing.T) {
	e := aqSetup(t)
	aaKey, aaCert := aqKeyPair(t)
	e.sp.IDPMetadata.AttributeAuthorityDescriptors[0].KeyDescriptors = []KeyDescriptor{{
		Use: "signing",
		KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{
			{Data: base64.StdEncoding.EncodeToString(aaCert.Raw)},
		}}},
	}}
	aaSign := func(el *etree.Element) *etree.Element { return spcovSign(t, aaKey, aaCert, el) }

	query := e.aqQuery(t)
	_, err := e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true, sign: aaSign}), query)
	assert.NilError(t, err)

	query = e.aqQuery(t)
	_, err = e.sp.ParseXMLAttributeQueryResponse(e.aqSOAP(t, query, aqOptions{signResponse: true}), query)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))

	// Logins are still verified with the IdP SSO key only.
	_, err = e.sp.ParseXMLResponse(spcovSerialize(t, aaSign(e.response().Element())), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "cannot validate signature on Response"))
}

func TestParseXMLAttributeQueryResponseEnvelope(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)
	signedResponse := func() *etree.Element { return e.aqResponseEl(t, query, aqOptions{signResponse: true}) }
	envelope := func(body ...*etree.Element) []byte {
		env := etree.NewElement("soapenv:Envelope")
		env.CreateAttr("xmlns:soapenv", soapEnvelopeNamespace)
		bodyEl := env.CreateElement("soapenv:Body")
		for _, el := range body {
			bodyEl.AddChild(el)
		}
		return spcovSerialize(t, env)
	}
	foreign := func(el *etree.Element) *etree.Element {
		el.Space = "evil"
		el.CreateAttr("xmlns:evil", "urn:example:evil")
		return el
	}

	testCases := []struct {
		name string
		buf  func() []byte
		err  string
	}{
		{"not XML", func() []byte { return []byte("not xml") }, "invalid xml: no root"},
		{"empty", func() []byte { return nil }, "invalid xml: no root"},
		{"bare Response", func() []byte { return spcovSerialize(t, signedResponse()) }, "expected a SOAP Envelope"},
		{"Envelope in another namespace", func() []byte {
			env := etree.NewElement("evil:Envelope")
			env.CreateAttr("xmlns:evil", "urn:example:evil")
			env.CreateElement("evil:Body").AddChild(signedResponse())
			return spcovSerialize(t, env)
		}, "expected a SOAP Envelope"},
		{"Body in another namespace", func() []byte {
			env := etree.NewElement("soapenv:Envelope")
			env.CreateAttr("xmlns:soapenv", soapEnvelopeNamespace)
			body := env.CreateElement("evil:Body")
			body.CreateAttr("xmlns:evil", "urn:example:evil")
			body.AddChild(signedResponse())
			return spcovSerialize(t, env)
		}, "cannot find http://schemas.xmlsoap.org/soap/envelope/:Body element"},
		{"two Bodies", func() []byte {
			env := etree.NewElement("soapenv:Envelope")
			env.CreateAttr("xmlns:soapenv", soapEnvelopeNamespace)
			env.CreateElement("soapenv:Body").AddChild(signedResponse())
			env.CreateElement("soapenv:Body").AddChild(signedResponse())
			return spcovSerialize(t, env)
		}, "expected exactly one http://schemas.xmlsoap.org/soap/envelope/:Body element"},
		{"empty Body", func() []byte { return envelope() }, "expected exactly one element in the SOAP Body, found 0"},
		{"Response in another namespace", func() []byte { return envelope(foreign(signedResponse())) },
			"cannot find urn:oasis:names:tc:SAML:2.0:protocol:Response element"},
		{"Response beside an element in another namespace", func() []byte {
			return envelope(foreign(etree.NewElement("Response")), signedResponse())
		}, "expected exactly one element in the SOAP Body, found 2"},
		{"two Responses", func() []byte { return envelope(signedResponse(), signedResponse()) },
			"expected exactly one element in the SOAP Body, found 2"},
		{"SOAP Fault", func() []byte {
			fault := etree.NewElement("soapenv:Fault")
			fault.CreateElement("faultcode").SetText("soapenv:Server")
			return envelope(fault)
		}, "the SOAP Body holds a Fault"},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := e.sp.ParseXMLAttributeQueryResponse(tc.buf(), query)
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), tc.err))
		})
	}
}

func TestParseXMLAttributeQueryResponseBadQuery(t *testing.T) {
	e := aqSetup(t)
	query := e.aqQuery(t)
	buf := e.aqSOAP(t, query, aqOptions{signResponse: true})
	for name, q := range map[string]*AttributeQuery{
		"nil":        nil,
		"no ID":      {Subject: query.Subject},
		"no Subject": {ID: query.ID},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := e.sp.ParseXMLAttributeQueryResponse(buf, q)
			assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "the attribute query has no ID or no Subject NameID"))
		})
	}
}

func TestParseXMLAttributeQueryResponseReplayCache(t *testing.T) {
	e := aqSetup(t)
	cache := memoryReplayCache{}
	e.sp.ReplayCache = cache
	query := e.aqQuery(t)
	buf := e.aqSOAP(t, query, aqOptions{signResponse: true})

	_, err := e.sp.ParseXMLAttributeQueryResponse(buf, query)
	assert.NilError(t, err)
	assert.Check(t, is.Equal(cache["id-assertion"], spcovNow.Add(MaxIssueDelay)))

	_, err = e.sp.ParseXMLAttributeQueryResponse(buf, query)
	assert.Check(t, errors.Is(spcovPrivateErr(t, err), ErrAssertionReplayed))
}

// The browser SSO profile still requires a bearer SubjectConfirmation: an
// assertion shaped like an attribute query answer does not log anyone in.
func TestParseXMLResponseStillRequiresBearer(t *testing.T) {
	e := aqSetup(t)
	response := e.response()
	assertion := e.assertion()
	assertion.Subject.SubjectConfirmations[0].Method = aqSenderVouches
	response.Assertion = assertion
	buf := spcovSerialize(t, e.idpSign(t, response.Element()))
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "assertion has no bearer SubjectConfirmation"))
}

// aqServer is an attribute authority that answers each query with respond.
type aqServer struct {
	*httptest.Server
	requests [][]byte
	headers  []http.Header
	status   int
	respond  func(query *AttributeQuery) []byte
}

func newAQServer(t *testing.T, e *spcovEnv) *aqServer {
	t.Helper()
	s := &aqServer{status: http.StatusOK}
	s.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		s.requests = append(s.requests, body)
		s.headers = append(s.headers, r.Header.Clone())
		var query AttributeQuery
		doc := etree.NewDocument()
		if err := doc.ReadFromBytes(body); err == nil {
			if el := doc.FindElement("/Envelope/Body/AttributeQuery"); el != nil {
				_ = unmarshalElement(el, &query)
			}
		}
		w.Header().Set("Content-Type", "text/xml")
		w.WriteHeader(s.status)
		_, _ = w.Write(s.respond(&query))
	}))
	t.Cleanup(s.Close)
	e.sp.IDPMetadata.AttributeAuthorityDescriptors[0].AttributeServices[0].Location = s.URL
	e.sp.HTTPClient = s.Client()
	return s
}

func TestQueryAttributes(t *testing.T) {
	e := aqSetup(t)
	s := newAQServer(t, e)
	s.respond = func(query *AttributeQuery) []byte {
		return e.aqSOAP(t, query, aqOptions{signAssertion: true, encrypt: true})
	}

	result, err := e.sp.QueryAttributes(context.Background(), aqNameID, Attribute{Name: aqMailOID, NameFormat: aqURINameFormat})
	assert.NilError(t, err)
	assert.Assert(t, is.Len(result.Attributes, 1))
	assert.Check(t, is.Equal(result.Attributes[0].Values[0].Value, "alice@example.com"))

	// What the attribute authority received: a signed query in a SOAP
	// envelope, sent with the SOAP binding's headers.
	assert.Assert(t, is.Len(s.requests, 1))
	assert.Check(t, is.Equal(s.headers[0].Get("Content-Type"), "text/xml; charset=utf-8"))
	assert.Check(t, is.Equal(s.headers[0].Get("SOAPAction"), "http://www.oasis-open.org/committees/security"))
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(s.requests[0]))
	assert.Check(t, is.Equal(doc.Root().NamespaceURI(), soapEnvelopeNamespace))
	queryEl := doc.FindElement("/Envelope/Body/AttributeQuery")
	assert.Assert(t, queryEl != nil)
	assert.Check(t, is.Equal(queryEl.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:protocol"))
	assert.Check(t, is.Equal(queryEl.SelectAttrValue("Destination", ""), s.URL))
	aqVerify(t, e, queryEl)
}

func TestQueryAttributesErrors(t *testing.T) {
	t.Run("HTTP error status", func(t *testing.T) {
		e := aqSetup(t)
		s := newAQServer(t, e)
		s.status = http.StatusInternalServerError
		s.respond = func(*AttributeQuery) []byte { return []byte("<soapenv:Envelope/>") }
		_, err := e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.Check(t, is.ErrorContains(err, "HTTP status 500"))
	})
	t.Run("oversized response", func(t *testing.T) {
		e := aqSetup(t)
		old := MaxAttributeQueryResponseSize
		t.Cleanup(func() { MaxAttributeQueryResponseSize = old })
		MaxAttributeQueryResponseSize = 4096
		s := newAQServer(t, e)
		var size int
		s.respond = func(query *AttributeQuery) []byte {
			buf := e.aqSOAP(t, query, aqOptions{signResponse: true})
			size = len(buf)
			return append(buf, bytes.Repeat([]byte(" "), 4096)...)
		}
		_, err := e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.Check(t, is.ErrorContains(err, "response body is larger than 4096 bytes"))

		// At the limit, it is accepted.
		MaxAttributeQueryResponseSize = int64(size + 4096)
		_, err = e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.NilError(t, err)
	})
	t.Run("invalid response", func(t *testing.T) {
		e := aqSetup(t)
		s := newAQServer(t, e)
		s.respond = func(query *AttributeQuery) []byte { return e.aqSOAP(t, query, aqOptions{}) }
		_, err := e.sp.QueryAttributes(context.Background(), aqNameID)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "neither the Response nor its Assertion is signed"))
	})
	t.Run("cancelled context", func(t *testing.T) {
		e := aqSetup(t)
		s := newAQServer(t, e)
		s.respond = func(query *AttributeQuery) []byte { return e.aqSOAP(t, query, aqOptions{signResponse: true}) }
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		_, err := e.sp.QueryAttributes(ctx, aqNameID)
		assert.Check(t, errors.Is(err, context.Canceled), "%v", err)
		assert.Check(t, is.Len(s.requests, 0))
	})
}

func TestGetAttributeServiceLocation(t *testing.T) {
	e := aqSetup(t)
	assert.Check(t, is.Equal(e.sp.GetAttributeServiceLocation(SOAPBinding), aqLocation))
	assert.Check(t, is.Equal(e.sp.GetAttributeServiceLocation(HTTPPostBinding), ""))
	e.sp.IDPMetadata = nil
	assert.Check(t, is.Equal(e.sp.GetAttributeServiceLocation(SOAPBinding), ""))
}
