package saml

// Tests pinning behavior required by the SAML V2.0 Profiles specification
// (saml-profiles-2.0-os). Each test cites the section and the requirement it
// checks.

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

const specProfEntityFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"

// specProfAssertIssuer checks the Issuer rule shared by saml-profiles
// §4.1.4.1, §4.1.4.2, §4.4.4.1, §4.4.4.2, §5.4.1 and §6.4.1: the Issuer is
// present, names the entity, and its Format is omitted or entity.
func specProfAssertIssuer(t *testing.T, issuer *Issuer, entityID string) {
	t.Helper()
	assert.Assert(t, issuer != nil, "Issuer must be present")
	assert.Check(t, is.Equal(entityID, issuer.Value))
	assert.Check(t, issuer.Format == "" || issuer.Format == specProfEntityFormat,
		"Issuer Format must be omitted or entity, got %q", issuer.Format)
}

// specProfParse parses a Response whose single (unsigned) assertion is built
// from e.assertion() and the Response from e.response(), after applying the
// mutators, with the Response signed by the IdP.
func specProfParse(t *testing.T, e *spcovEnv, possibleRequestIDs []string, mutateAssertion func(*Assertion), mutateResponse func(*Response)) (*Assertion, error) {
	t.Helper()
	a := e.assertion()
	if mutateAssertion != nil {
		mutateAssertion(a)
	}
	r := e.response()
	if mutateResponse != nil {
		mutateResponse(r)
	}
	r.Assertion = a
	return e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), possibleRequestIDs, e.sp.AcsURL)
}

// specProfIDPTest returns NewIdentityProviderTest(t, applyKey), restoring the
// package globals it replaces when the test ends.
func specProfIDPTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
	t.Cleanup(func() {
		TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader
	})
	return NewIdentityProviderTest(t, applyKey)
}

// specProfAuthnRequest returns an IdpAuthnRequest for an AuthnRequest from
// test.SP with the given extra XML attributes on the AuthnRequest element.
func specProfAuthnRequest(test *IdentityProviderTest, attrs string) *IdpAuthnRequest {
	req := &IdpAuthnRequest{
		Now: TimeNow(),
		IDP: &test.IDP,
		RequestBuffer: []byte(`<AuthnRequest xmlns="urn:oasis:names:tc:SAML:2.0:protocol" ` +
			`ID="id-specprof-request" IssueInstant="2015-12-01T01:57:09Z" Version="2.0" ` + attrs + `>` +
			`<Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` + test.SP.MetadataURL.String() + `</Issuer>` +
			`</AuthnRequest>`),
	}
	req.HTTPRequest = httptest.NewRequest(http.MethodPost, test.IDP.SSOURL.String(), nil)
	return req
}

// specProfServeSPMetadata makes the IdP of test see md as the metadata of
// test.SP.
func specProfServeSPMetadata(test *IdentityProviderTest, md *EntityDescriptor) {
	test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
		GetServiceProviderFunc: func(_ *http.Request, id string) (*EntityDescriptor, error) {
			if id != test.SP.MetadataURL.String() {
				return nil, errors.New("unexpected service provider " + id)
			}
			return md, nil
		},
	}
}

// saml-profiles §4.1.4.1: "The <Issuer> element MUST be present and MUST
// contain the unique identifier of the requesting service provider; the Format
// attribute MUST be omitted or have a value of ...:nameid-format:entity." and
// "If the service provider wishes to permit the identity provider to establish
// a new identifier for the principal if none exists, it MUST include a
// <NameIDPolicy> element with the AllowCreate attribute set to "true"." The
// request "MUST NOT contain any <SubjectConfirmation> elements".
func TestSpecProfile_4_1_4_1_AuthnRequestIssuerAndNameIDPolicy(t *testing.T) {
	e := spcovSetup(t)
	for _, entityID := range []string{"", "urn:example:sp"} {
		e.sp.EntityID = entityID
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso/redirect", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		specProfAssertIssuer(t, req.Issuer, e.sp.Metadata().EntityID)
		assert.Assert(t, req.NameIDPolicy != nil && req.NameIDPolicy.AllowCreate != nil)
		assert.Check(t, *req.NameIDPolicy.AllowCreate)
		assert.Check(t, req.Subject == nil || len(req.Subject.SubjectConfirmations) == 0)
	}
}

// saml-profiles §4.1.4.1: "the identity provider MUST ensure that any
// <AssertionConsumerServiceURL> or <AssertionConsumerServiceIndex> elements
// in the request are verified as belonging to the service provider to whom
// the response will be sent."
func TestSpecProfile_4_1_4_1_IdPVerifiesRequestedACS(t *testing.T) {
	test := specProfIDPTest(t)

	req := specProfAuthnRequest(test, `AssertionConsumerServiceURL="https://evil.example.com/acs"`)
	err := req.Validate()
	assert.Check(t, errors.Is(err, ErrUnknownAssertionConsumerService), "got %v", err)

	req = specProfAuthnRequest(test, `AssertionConsumerServiceIndex="42"`)
	err = req.Validate()
	assert.Check(t, errors.Is(err, ErrUnknownAssertionConsumerService), "got %v", err)

	req = specProfAuthnRequest(test, `AssertionConsumerServiceURL="`+test.SP.AcsURL.String()+`"`)
	assert.NilError(t, req.Validate())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), req.ACSEndpoint.Location))
}

// saml-profiles §4.1.6: "The isDefault attribute is used to specify the
// endpoint to use if not specified in a request."
func TestSpecProfile_4_1_6_IdPUsesDefaultACSWhenUnspecified(t *testing.T) {
	test := specProfIDPTest(t)
	md := test.SP.Metadata()
	isDefault := true
	md.SPSSODescriptors[0].AssertionConsumerServices = []IndexedEndpoint{
		{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/first", Index: 0},
		{Binding: HTTPPostBinding, Location: "https://sp.example.com/acs/default", Index: 1, IsDefault: &isDefault},
	}
	specProfServeSPMetadata(test, md)

	req := specProfAuthnRequest(test, "")
	assert.NilError(t, req.Validate())
	assert.Check(t, is.Equal("https://sp.example.com/acs/default", req.ACSEndpoint.Location))
}

// saml-profiles §4.1.2 step 5: for the <Response>, "The HTTP Redirect binding
// MUST NOT be used". The IdP refuses to deliver a Response to an ACS endpoint
// that has the HTTP-Redirect binding.
func TestSpecProfile_4_1_2_IdPDoesNotSendResponseWithRedirectBinding(t *testing.T) {
	test := specProfIDPTest(t)
	md := test.SP.Metadata()
	md.SPSSODescriptors[0].AssertionConsumerServices = []IndexedEndpoint{
		{Binding: HTTPRedirectBinding, Location: test.SP.AcsURL.String(), Index: 0},
	}
	specProfServeSPMetadata(test, md)

	req := specProfAuthnRequest(test, `AssertionConsumerServiceURL="`+test.SP.AcsURL.String()+`"`)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", NameID: "alice", Index: "idx"}))
	w := httptest.NewRecorder()
	err := req.WriteResponse(w)
	assert.Check(t, errors.Is(err, ErrUnsupported), "got %v", err)
	assert.Check(t, is.Equal("", w.Header().Get("Location")))
}

// saml-profiles §4.1.4.2 (<Response> Usage), for a response the IdP makes:
//   - the Response Issuer, if present, and each assertion Issuer contain the
//     IdP's unique identifier, with Format omitted or entity;
//   - the assertion has an <AuthnStatement>, with a SessionIndex since the
//     IdP supports Single Logout;
//   - it has a bearer <SubjectConfirmation> whose <SubjectConfirmationData>
//     has Recipient (the ACS URL) and NotOnOrAfter, InResponseTo equal to the
//     request ID, and no NotBefore ("It MUST NOT contain a NotBefore
//     attribute");
//   - it has an <AudienceRestriction> with the SP's unique identifier.
//
// saml-profiles §4.1.3.5 / §4.1.4.5: with the HTTP POST binding the
// assertion MUST be signed.
func TestSpecProfile_4_1_4_2_IdPResponseContents(t *testing.T) {
	test := specProfIDPTest(t)
	test.IDP.LogoutURL = mustParseURL("https://idp.example.com/saml/slo")

	req := specProfAuthnRequest(test, `AssertionConsumerServiceURL="`+test.SP.AcsURL.String()+`" `+
		`ProtocolBinding="`+HTTPPostBinding+`"`)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID: "s", NameID: "alice", Index: "session-index", CreateTime: TimeNow(),
	}))
	assert.NilError(t, req.MakeResponse())

	idpEntityID := test.IDP.Metadata().EntityID
	a := req.Assertion

	// Issuers
	var response Response
	assert.NilError(t, unmarshalEtreeHack(req.ResponseEl.Copy(), &response))
	specProfAssertIssuer(t, response.Issuer, idpEntityID)
	specProfAssertIssuer(t, &a.Issuer, idpEntityID)
	assert.Check(t, is.Equal(req.Request.ID, response.InResponseTo))
	assert.Check(t, is.Equal(StatusSuccess, response.Status.StatusCode.Value))

	// The assertion is signed (it is then encrypted for this SP).
	assert.Check(t, a.Signature != nil, "assertion must be signed for HTTP-POST")
	assert.Check(t, is.Equal(HTTPPostBinding, req.ACSEndpoint.Binding))

	// AuthnStatement with SessionIndex
	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	assert.Check(t, is.Equal("session-index", a.AuthnStatements[0].SessionIndex))

	// bearer SubjectConfirmation
	assert.Assert(t, a.Subject != nil)
	assert.Assert(t, is.Len(a.Subject.SubjectConfirmations, 1))
	sc := a.Subject.SubjectConfirmations[0]
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:cm:bearer", sc.Method))
	assert.Assert(t, sc.SubjectConfirmationData != nil)
	scd := sc.SubjectConfirmationData
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), scd.Recipient))
	assert.Check(t, scd.NotOnOrAfter.After(req.Now))
	assert.Check(t, scd.NotBefore.IsZero(), "bearer SubjectConfirmationData MUST NOT contain NotBefore")
	assert.Check(t, is.Equal(req.Request.ID, scd.InResponseTo))
	scdEl := sc.Element().FindElement("./SubjectConfirmationData")
	assert.Assert(t, scdEl != nil)
	assert.Check(t, scdEl.SelectAttr("NotBefore") == nil)

	// AudienceRestriction naming the SP
	assert.Assert(t, a.Conditions != nil)
	assert.Assert(t, is.Len(a.Conditions.AudienceRestrictions, 1))
	assert.Check(t, audienceRestrictionContains(&a.Conditions.AudienceRestrictions[0], test.SP.MetadataURL.String()))
}

// saml-profiles §4.1.5: "An unsolicited <Response> MUST NOT contain an
// InResponseTo attribute, nor should any bearer <SubjectConfirmationData>
// elements contain one."
func TestSpecProfile_4_1_5_IdPUnsolicitedResponseHasNoInResponseTo(t *testing.T) {
	test := specProfIDPTest(t)
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/login/sp", nil)
	req, err := test.IDP.NewIdpInitiatedRequest(r, test.SP.MetadataURL.String(), "")
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", NameID: "alice", Index: "idx"}))
	assert.NilError(t, req.MakeResponse())

	assert.Check(t, req.ResponseEl.SelectAttr("InResponseTo") == nil)
	for _, sc := range req.Assertion.Subject.SubjectConfirmations {
		assert.Check(t, sc.Element().FindElement("./SubjectConfirmationData[@InResponseTo]") == nil)
	}
}

// saml-profiles §4.1.4.3: the SP MUST "Verify that the Recipient attribute in
// any bearer <SubjectConfirmationData> matches the assertion consumer service
// URL to which the <Response> or artifact was delivered". §4.1.4.2 requires
// the Recipient attribute to be present.
func TestSpecProfile_4_1_4_3_RecipientMustMatchACS(t *testing.T) {
	e := spcovSetup(t)
	for name, recipient := range map[string]string{
		"other ACS": "https://other.example.com/saml/acs",
		"missing":   "",
	} {
		t.Run(name, func(t *testing.T) {
			_, err := specProfParse(t, e, []string{spcovRequestID}, func(a *Assertion) {
				a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = recipient
			}, nil)
			assert.Check(t, errors.Is(err, ErrDestinationMismatch), "got %v", err)
		})
	}
	_, err := specProfParse(t, e, []string{spcovRequestID}, nil, nil)
	assert.NilError(t, err)
}

// saml-profiles §4.1.4.3: the SP MUST "Verify that the NotOnOrAfter attribute
// in any bearer <SubjectConfirmationData> has not passed, subject to
// allowable clock skew between the providers". §4.1.4.2 requires the
// NotOnOrAfter attribute to be present.
func TestSpecProfile_4_1_4_3_SubjectConfirmationNotOnOrAfter(t *testing.T) {
	e := spcovSetup(t)
	setNotOnOrAfter := func(d time.Time) func(*Assertion) {
		return func(a *Assertion) { a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = d }
	}

	_, err := specProfParse(t, e, []string{spcovRequestID}, setNotOnOrAfter(spcovNow.Add(-MaxClockSkew-time.Second)), nil)
	assert.Check(t, errors.Is(err, ErrExpired), "passed beyond the clock skew: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, setNotOnOrAfter(time.Time{}), nil)
	assert.Check(t, errors.Is(err, ErrExpired), "missing: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, setNotOnOrAfter(spcovNow.Add(-MaxClockSkew/2)), nil)
	assert.Check(t, err, "passed, but within the allowed clock skew")
}

// saml-profiles §4.1.4.3: the SP MUST "Verify that the InResponseTo attribute
// in the bearer <SubjectConfirmationData> equals the ID of its original
// <AuthnRequest> message"; §4.1.4.2 requires the same of the Response.
func TestSpecProfile_4_1_4_3_InResponseToMustMatchRequest(t *testing.T) {
	e := spcovSetup(t)

	_, err := specProfParse(t, e, []string{"id-other-request"}, nil, nil)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "Response and assertion for another request: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, func(a *Assertion) {
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "id-other-request"
	}, nil)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "SubjectConfirmationData for another request: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, nil, func(r *Response) { r.InResponseTo = "id-other-request" })
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "Response for another request: got %v", err)

	// A solicited response missing InResponseTo is not accepted when
	// unsolicited responses are not allowed.
	_, err = specProfParse(t, e, []string{spcovRequestID}, func(a *Assertion) {
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = ""
	}, func(r *Response) { r.InResponseTo = "" })
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "missing InResponseTo: got %v", err)
}

// saml-profiles §4.1.5: an unsolicited Response has no InResponseTo, and
// §4.1.4.3 says that for an unsolicited response "the attribute MUST NOT be
// present". With AllowIDPInitiated the SP accepts such a response; a
// non-empty InResponseTo must still match a request the SP made.
func TestSpecProfile_4_1_5_UnsolicitedResponses(t *testing.T) {
	e := spcovSetup(t)
	unsolicited := func(a *Assertion) { a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "" }
	noResponseInResponseTo := func(r *Response) { r.InResponseTo = "" }

	e.sp.AllowIDPInitiated = true
	_, err := specProfParse(t, e, nil, unsolicited, noResponseInResponseTo)
	assert.NilError(t, err)

	_, err = specProfParse(t, e, nil, nil, noResponseInResponseTo)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch),
		"SubjectConfirmationData InResponseTo naming no request of this SP: got %v", err)

	_, err = specProfParse(t, e, nil, unsolicited, func(r *Response) { r.InResponseTo = "id-unknown" })
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "Response InResponseTo naming no request of this SP: got %v", err)

	e.sp.AllowIDPInitiated = false
	_, err = specProfParse(t, e, nil, unsolicited, noResponseInResponseTo)
	assert.Check(t, errors.Is(err, ErrRequestIDMismatch), "unsolicited response without AllowIDPInitiated: got %v", err)
}

// saml-profiles §4.1.4.2 (lines 547-550): "The set of one or more assertions
// MUST contain at least one <AuthnStatement> that reflects the
// authentication of the principal to the identity provider." An assertion
// without one, such as an attribute-only assertion, does not establish a
// login.
func TestSpecProfile_4_1_4_2_AuthnStatementRequired(t *testing.T) {
	e := spcovSetup(t)
	parse := func(a *Assertion) (*Assertion, error) {
		r := e.response()
		r.Assertion = a
		return e.sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, e.sp.AcsURL)
	}

	got, err := parse(e.assertion())
	assert.NilError(t, err)
	assert.Check(t, is.Len(got.AuthnStatements, 1))

	attributeOnly := e.assertion()
	attributeOnly.AuthnStatements = nil
	attributeOnly.AttributeStatements = []AttributeStatement{{Attributes: []Attribute{{
		Name: "urn:oid:0.9.2342.19200300.100.1.3", Values: []AttributeValue{{Value: "alice@example.com"}},
	}}}}
	_, err = parse(attributeOnly)
	assert.Check(t, errors.Is(err, ErrMissingElement), "%v", err)
	assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "assertion has no AuthnStatement"))
}

// saml-profiles §4.1.4.2: "The <Issuer> element MAY be omitted, but if
// present it MUST contain the unique identifier of the issuing identity
// provider" and "Each assertion's <Issuer> element MUST contain the unique
// identifier of the issuing identity provider".
func TestSpecProfile_4_1_4_2_IssuerMustBeTheIdP(t *testing.T) {
	e := spcovSetup(t)

	_, err := specProfParse(t, e, []string{spcovRequestID}, nil, func(r *Response) { r.Issuer = &Issuer{Value: "https://other-idp.example.com/"} })
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "Response Issuer: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, func(a *Assertion) { a.Issuer.Value = "https://other-idp.example.com/" }, nil)
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "assertion Issuer: got %v", err)

	_, err = specProfParse(t, e, []string{spcovRequestID}, nil, func(r *Response) { r.Issuer = nil })
	assert.Check(t, err, "the Response Issuer MAY be omitted")
}

// saml-profiles §4.1.4.2: "If the identity provider wishes to return an
// error, it MUST NOT include any assertions in the <Response> message." The
// SP does not accept an assertion from a Response with an error status.
func TestSpecProfile_4_1_4_2_ErrorStatusIsNotAccepted(t *testing.T) {
	e := spcovSetup(t)
	_, err := specProfParse(t, e, []string{spcovRequestID}, nil, func(r *Response) {
		r.Status = Status{StatusCode: StatusCode{Value: StatusRequester}}
	})
	var badStatus ErrBadStatus
	assert.Assert(t, errors.As(err, &badStatus), "got %v", err)
	assert.Check(t, is.Equal(StatusRequester, badStatus.Status))
}

// saml-profiles §4.1.4.5: "If the HTTP POST binding is used to deliver the
// <Response>, the enclosed assertion(s) MUST be signed." and §4.1.4.3 "Verify
// any signatures present on the assertion(s) or the response". A Response
// with neither the Response nor the assertion signed is rejected, as is one
// whose assertion signature is not made by the IdP.
func TestSpecProfile_4_1_4_5_UnsignedOrUntrustedAssertionRejected(t *testing.T) {
	e := spcovSetup(t)

	r := e.response()
	r.Assertion = e.assertion()
	_, err := e.sp.ParseXMLResponse(spcovSerialize(t, r.Element()), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(spcovPrivateErr(t, err), errSignatureElementNotPresent), "unsigned: got %v", err)

	otherKey := mustParsePrivateKey(golden.Get(t, "key_2017.pem"))
	otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	respEl := e.response().Element()
	respEl.AddChild(spcovSign(t, otherKey, otherCert, e.assertion().Element()))
	_, err = e.sp.ParseXMLResponse(spcovSerialize(t, respEl), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "signed by an untrusted key: got %v", err)

	respEl = e.response().Element()
	respEl.AddChild(e.idpSign(t, e.assertion().Element()))
	_, err = e.sp.ParseXMLResponse(spcovSerialize(t, respEl), []string{spcovRequestID}, e.sp.AcsURL)
	assert.Check(t, err, "assertion signed by the IdP")
}

// saml-profiles §4.1.2 step 5: "The HTTP Redirect binding MUST NOT be used"
// to deliver the <Response>. ParseResponse does not take a SAMLResponse from
// the URL query.
func TestSpecProfile_4_1_2_ResponseNotAcceptedFromQuery(t *testing.T) {
	e := spcovSetup(t)
	r := e.response()
	r.Assertion = e.assertion()
	buf := spcovSerialize(t, e.idpSign(t, r.Element()))
	q := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(spcovDeflate(t, buf))}}
	req := httptest.NewRequest(http.MethodGet, e.sp.AcsURL.String()+"?"+q.Encode(), nil)
	assert.NilError(t, req.ParseForm())
	_, err := e.sp.ParseResponse(req, []string{spcovRequestID})
	assert.Check(t, err != nil)
}

// saml-profiles §4.4.4.1: the LogoutRequest "<Issuer> element MUST be present
// and MUST contain the unique identifier of the requesting entity; the Format
// attribute MUST be omitted or have a value of ...entity". §4.4.3.1: a session
// participant includes "one or more applicable <SessionIndex> elements" and
// "The <LogoutRequest> message MUST be signed if the HTTP POST or Redirect
// binding is used" (with SignatureMethod set, both bindings sign).
func TestSpecProfile_4_4_4_1_SPLogoutRequest(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo/post", "alice@example.com", WithSessionIndex("idx-1"))
	assert.NilError(t, err)
	specProfAssertIssuer(t, req.Issuer, e.sp.Metadata().EntityID)
	assert.Assert(t, req.SessionIndex != nil)
	assert.Check(t, is.Equal("idx-1", req.SessionIndex.Value))
	assert.Check(t, req.Signature != nil, "HTTP-POST LogoutRequest must be signed")

	u, err := e.sp.MakeRedirectLogoutRequest("alice@example.com", "relay", WithSessionIndex("idx-1"))
	assert.NilError(t, err)
	assert.Check(t, u.Query().Get("Signature") != "", "HTTP-Redirect LogoutRequest must be signed")
	assert.Check(t, is.Equal(dsig.RSASHA256SignatureMethod, u.Query().Get("SigAlg")))
}

// saml-profiles §4.4.4.2: the LogoutResponse "<Issuer> element MUST be
// present and MUST contain the unique identifier of the responding entity".
// §4.4.3.4: "The <LogoutResponse> message MUST be signed if the HTTP POST or
// Redirect binding is used" (with SignatureMethod set, both bindings sign).
func TestSpecProfile_4_4_4_2_SPLogoutResponse(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	resp, err := e.sp.MakeLogoutResponse("https://idp.example.com/slo/post", "id-logout-request")
	assert.NilError(t, err)
	specProfAssertIssuer(t, resp.Issuer, e.sp.Metadata().EntityID)
	assert.Check(t, is.Equal("id-logout-request", resp.InResponseTo))
	assert.Check(t, resp.Signature != nil)

	u, err := e.sp.MakeRedirectLogoutResponse("id-logout-request", "relay")
	assert.NilError(t, err)
	assert.Check(t, u.Query().Get("Signature") != "")
}

// specProfLogoutRequestForm returns the base64 HTTP-POST form value of a
// LogoutRequest from the IdP to e.sp, signed by the IdP if sign is set.
func specProfLogoutRequestForm(t *testing.T, e *spcovEnv, sign bool, mutate func(*LogoutRequest)) string {
	t.Helper()
	req := &LogoutRequest{
		ID:           "id-idp-logout-request",
		Version:      "2.0",
		IssueInstant: spcovNow,
		Destination:  e.sp.SloURL.String(),
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		NameID:       &NameID{Value: "alice@example.com"},
		SessionIndex: &SessionIndex{Value: "idx-1"},
	}
	if mutate != nil {
		mutate(req)
	}
	el := req.Element()
	if sign {
		el = e.idpSign(t, el)
	}
	return base64.StdEncoding.EncodeToString(spcovSerialize(t, el))
}

// saml-profiles §4.4.4.1: "The requester MUST authenticate itself to the
// responder and ensure message integrity" and the Issuer "MUST be present".
// The SP refuses an HTTP-POST LogoutRequest that is unsigned, has no Issuer,
// or is not from its IdP.
func TestSpecProfile_4_4_4_1_SPRejectsUnauthenticatedLogoutRequest(t *testing.T) {
	e := spcovSetup(t)

	got, err := e.sp.ValidateLogoutRequestForm(specProfLogoutRequestForm(t, e, true, nil))
	assert.NilError(t, err)
	assert.Check(t, is.Equal("alice@example.com", got.NameID.Value))

	_, err = e.sp.ValidateLogoutRequestForm(specProfLogoutRequestForm(t, e, false, nil))
	assert.Check(t, err != nil, "unsigned LogoutRequest")

	_, err = e.sp.ValidateLogoutRequestForm(specProfLogoutRequestForm(t, e, true, func(r *LogoutRequest) { r.Issuer = nil }))
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "no Issuer: got %v", err)

	_, err = e.sp.ValidateLogoutRequestForm(specProfLogoutRequestForm(t, e, true, func(r *LogoutRequest) {
		r.Issuer = &Issuer{Value: "https://other-idp.example.com/"}
	}))
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "other Issuer: got %v", err)
}

// saml-profiles §4.4.4.2: "The responder MUST authenticate itself to the
// requester and ensure message integrity" and the Issuer "MUST be present".
// The SP refuses an HTTP-POST LogoutResponse that is unsigned or has no
// Issuer.
func TestSpecProfile_4_4_4_2_SPRejectsUnauthenticatedLogoutResponse(t *testing.T) {
	e := spcovSetup(t)

	assert.NilError(t, e.sp.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString(e.signedLogoutResponse(t, nil))))

	unsigned := spcovSerialize(t, e.logoutResponse().Element())
	assert.Check(t, e.sp.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString(unsigned)) != nil, "unsigned LogoutResponse")

	noIssuer := e.signedLogoutResponse(t, func(lr *LogoutResponse) { lr.Issuer = nil })
	err := e.sp.ValidateLogoutResponseForm(base64.StdEncoding.EncodeToString(noIssuer))
	assert.Check(t, errors.Is(err, ErrIssuerMismatch), "no Issuer: got %v", err)
}

// saml-profiles §4.4.4.2 and §4.4.3.5: the IdP answers a LogoutRequest with a
// LogoutResponse whose Issuer is present and names the IdP (Format omitted
// or entity), and which is signed for the HTTP-Redirect and HTTP-POST
// bindings.
func TestSpecProfile_4_4_4_2_IdPLogoutResponse(t *testing.T) {
	for _, binding := range []string{HTTPRedirectBinding, HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
			t.Cleanup(func() { TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader })
			test := newSLOTest(t)
			test.SP.LogoutBindings = []string{binding}
			req := test.logoutRequest()
			w := test.serve(test.signedPostRequest(t, req))

			resp := decodeLogoutResponse(t, w)
			specProfAssertIssuer(t, resp.Issuer, test.IDP.Metadata().EntityID)
			assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
			if binding == HTTPRedirectBinding {
				u, err := url.Parse(w.Header().Get("Location"))
				assert.NilError(t, err)
				assert.Check(t, u.Query().Get("Signature") != "")
			} else {
				assert.Check(t, resp.Signature != nil)
			}
		})
	}
}

// saml-profiles §4.4.3.1 / §4.4.4.1: "The <LogoutRequest> message MUST be
// signed if the HTTP POST or Redirect binding is used". The IdP refuses an
// unsigned LogoutRequest and answers it with no LogoutResponse.
func TestSpecProfile_4_4_4_1_IdPRejectsUnsignedLogoutRequest(t *testing.T) {
	oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
	t.Cleanup(func() { TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader })
	test := newSLOTest(t)
	w := test.serve(test.postRequest(t, test.logoutRequest()))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Len(test.sessions.invalidated, 0))
}

// saml-profiles §5.4.1: the ArtifactResolve "<Issuer> element MUST be present
// and MUST contain the unique identifier of the requesting entity; the Format
// attribute MUST be omitted or have a value of ...entity".
func TestSpecProfile_5_4_1_ArtifactResolveIssuer(t *testing.T) {
	e := spcovSetup(t)
	req, err := e.sp.MakeArtifactResolveRequest("artifact")
	assert.NilError(t, err)
	specProfAssertIssuer(t, req.Issuer, e.sp.Metadata().EntityID)
}

// saml-profiles §6.4.1: for the Assertion Query/Request profile "The <Issuer>
// element MUST be present", and §6.3.1 "The requester SHOULD authenticate
// itself": the query is signed when the SP has a key.
func TestSpecProfile_6_4_1_AttributeQueryIssuer(t *testing.T) {
	e := spcovSetup(t)
	e.sp.IDPMetadata.AttributeAuthorityDescriptors = []AttributeAuthorityDescriptor{{
		AttributeServices: []Endpoint{{Binding: SOAPBinding, Location: "https://idp.example.com/aa"}},
	}}
	q, err := e.sp.MakeAttributeQuery(NameID{Value: "alice@example.com"})
	assert.NilError(t, err)
	specProfAssertIssuer(t, q.Issuer, e.sp.Metadata().EntityID)
	assert.Check(t, q.Signature != nil)
}

// saml-profiles §8.1.4 (Basic Attribute Profile): "The xsi:type attribute
// MUST be present and be given the appropriate value." §8.1.2: the NameFormat
// MUST be ...attrname-format:basic. §8.2.2 (X.500/LDAP): the NameFormat MUST
// be ...attrname-format:uri for urn:oid: names. The IdP's default assertion
// maker follows these rules.
func TestSpecProfile_8_AttributeProfilesNameFormatAndType(t *testing.T) {
	test := specProfIDPTest(t)
	md := test.SP.Metadata()
	md.SPSSODescriptors[0].AttributeConsumingServices = []AttributeConsumingService{{
		Index: 0,
		RequestedAttributes: []RequestedAttribute{{Attribute: Attribute{
			Name: "email", NameFormat: "urn:oasis:names:tc:SAML:2.0:attrname-format:basic",
		}}},
	}}
	specProfServeSPMetadata(test, md)

	req := specProfAuthnRequest(test, "")
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID: "s", NameID: "alice", UserEmail: "alice@example.com", UserGivenName: "Alice",
	}))

	var sawBasic, sawOID bool
	for _, attrEl := range req.Assertion.Element().FindElements(".//Attribute") {
		name := attrEl.SelectAttrValue("Name", "")
		nameFormat := attrEl.SelectAttrValue("NameFormat", "")
		switch {
		case name == "email":
			sawBasic = true
			assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:attrname-format:basic", nameFormat))
		case strings.HasPrefix(name, "urn:oid:"):
			sawOID = true
			assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:attrname-format:uri", nameFormat), name)
		}
		for _, valueEl := range attrEl.FindElements("./AttributeValue") {
			assert.Check(t, is.Equal("xs:string", specProfXSIType(valueEl)), name)
		}
	}
	assert.Check(t, sawBasic)
	assert.Check(t, sawOID)
}

// specProfXSIType returns the xsi:type of el.
func specProfXSIType(el *etree.Element) string {
	for _, attr := range el.Attr {
		if attr.Key == "type" && attr.NamespaceURI() == "http://www.w3.org/2001/XMLSchema-instance" {
			return attr.Value
		}
	}
	return ""
}
