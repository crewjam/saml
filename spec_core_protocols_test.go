package saml

// Tests that pin behavior required by the SAML 2.0 core specification,
// section 3 (protocols), as amended by the approved errata
// (sstc-saml-core-errata-2.0-wd-07). Each test cites the section and the
// requirement it checks.

import (
	"encoding/xml"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/xmlenc"
)

// specProtoSSORequest runs an SP-initiated AuthnRequest made by test.SP
// through the IdP's Validate, MakeAssertion and MakeResponse, for a session
// of alice.
func specProtoSSORequest(t *testing.T, test *IdentityProviderTest) *IdpAuthnRequest {
	t.Helper()
	u, err := test.SP.MakeRedirectAuthenticationRequest("relay")
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, httptest.NewRequest(http.MethodGet, u.String(), nil))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{
		ID: "session-1", NameID: "alice@example.com", Index: "index-1", CreateTime: TimeNow(),
	}))
	assert.NilError(t, req.MakeResponse())
	return req
}

// specProtoSLOTest is newSLOTest, restoring the package globals it changes.
func specProtoSLOTest(t *testing.T) *sloTest {
	t.Helper()
	oldTimeNow, oldRandReader, oldXMLEncRandReader := TimeNow, RandReader, xmlenc.RandReader
	t.Cleanup(func() {
		TimeNow, RandReader, xmlenc.RandReader = oldTimeNow, oldRandReader, oldXMLEncRandReader
	})
	return newSLOTest(t)
}

// saml-core-2.0-os §3.2.2 (StatusResponseType): ID, Version ("2.0") and
// IssueInstant are required, and InResponseTo "MUST be present and its value
// MUST match the value of the corresponding request's ID attribute" when the
// response answers a request. <Status> is required, and the IdP's Response
// carries the Destination it is sent to.
func TestSpecProtocol_3_2_2_ResponseRequiredAttributes(t *testing.T) {
	test := idpcovNewTest(t)
	req := specProtoSSORequest(t, test)
	assert.Assert(t, req.Request.ID != "")

	el := req.ResponseEl
	assert.Check(t, is.Equal("Response", el.Tag))
	assert.Check(t, el.SelectAttrValue("ID", "") != "")
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))
	assert.Check(t, is.Equal(TimeNow().Format(timeFormat), el.SelectAttrValue("IssueInstant", "")))
	assert.Check(t, is.Equal(req.Request.ID, el.SelectAttrValue("InResponseTo", "")))
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), el.SelectAttrValue("Destination", "")))
	assert.Check(t, is.Equal(test.IDP.MetadataURL.String(), el.FindElement("./Issuer").Text()))
	statusCode := el.FindElement("./Status/StatusCode")
	assert.Assert(t, statusCode != nil)
	assert.Check(t, is.Equal(StatusSuccess, statusCode.SelectAttrValue("Value", "")))
}

// saml-core-2.0-os §3.2.2: "If the response is not generated in response to
// a request ... then this attribute [InResponseTo] MUST NOT be present." An
// IdP-initiated (unsolicited) Response, and the bearer
// SubjectConfirmationData of its assertion, carry no InResponseTo.
func TestSpecProtocol_3_2_2_UnsolicitedResponseOmitsInResponseTo(t *testing.T) {
	test := idpcovNewTest(t)
	r := httptest.NewRequest(http.MethodGet, "https://idp.example.com/saml/idp-initiated", nil)
	req, err := test.IDP.NewIdpInitiatedRequest(r, test.SP.MetadataURL.String(), "")
	assert.NilError(t, err)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{NameID: "alice@example.com"}))
	assert.NilError(t, req.MakeResponse())

	assert.Check(t, req.ResponseEl.SelectAttr("InResponseTo") == nil)
	scd := req.Assertion.Element().FindElement("./Subject/SubjectConfirmation/SubjectConfirmationData")
	assert.Assert(t, scd != nil)
	assert.Check(t, scd.SelectAttr("InResponseTo") == nil)
}

// saml-core-2.0-os §3.2.2: the Response ID "MUST follow the requirements
// specified in Section 1.3.4 for identifier uniqueness". Two responses (and
// their assertions) never share an identifier.
func TestSpecProtocol_3_2_2_ResponseIDsAreUnique(t *testing.T) {
	test := idpcovNewTest(t)
	first := specProtoSSORequest(t, test)
	second := specProtoSSORequest(t, test)
	assert.Check(t, first.ResponseEl.SelectAttrValue("ID", "") != second.ResponseEl.SelectAttrValue("ID", ""))
	assert.Check(t, first.Assertion.ID != second.Assertion.ID)
	assert.Check(t, first.Assertion.ID != first.ResponseEl.SelectAttrValue("ID", ""))
}

// saml-core-2.0-os §3.2.1 (Destination): "If it is present, the actual
// recipient MUST check that the URI reference identifies the location at
// which the message was received. If it does not, the request MUST be
// discarded." ServeSSO answers such a request with HTTP 400, without asking
// the SessionProvider for a session and without issuing a Response.
func TestSpecProtocol_3_2_1_DestinationMismatchDiscarded(t *testing.T) {
	test := idpcovNewTest(t)
	calls := 0
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
		calls++
		return &Session{NameID: "alice@example.com"}
	}}
	authnRequest, err := test.SP.MakeAuthenticationRequest("https://other-idp.example.com/sso", HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	u, err := authnRequest.Redirect("relay", &test.SP)
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, httptest.NewRequest(http.MethodGet, test.IDP.SSOURL.String()+"?"+u.RawQuery, nil))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Equal(0, calls))
	assert.Check(t, !strings.Contains(w.Body.String(), "SAMLResponse"))
}

// saml-core-2.0-os §3.4.1.4: the returned assertion "MUST contain a
// <saml:Subject> element that represents the presenter", at least one
// statement "MUST be a <saml:AuthnStatement>", and the assertion "MUST
// contain a <saml:AudienceRestriction> element referencing the requester".
// The presenter is the only attesting entity (bearer confirmation tied to
// the request and the ACS).
func TestSpecProtocol_3_4_1_4_AssertionContents(t *testing.T) {
	test := idpcovNewTest(t)
	req := specProtoSSORequest(t, test)
	a := req.Assertion

	assert.Assert(t, a.Subject != nil && a.Subject.NameID != nil)
	assert.Check(t, is.Equal("alice@example.com", a.Subject.NameID.Value))
	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	assert.Check(t, is.Equal("index-1", a.AuthnStatements[0].SessionIndex))

	assert.Assert(t, a.Conditions != nil)
	audiences := make([]string, 0, len(a.Conditions.AudienceRestrictions))
	for _, ar := range a.Conditions.AudienceRestrictions {
		audiences = append(audiences, ar.Audience.Value)
	}
	assert.Check(t, is.Contains(audiences, test.SP.MetadataURL.String()))

	assert.Assert(t, is.Len(a.Subject.SubjectConfirmations, 1))
	sc := a.Subject.SubjectConfirmations[0]
	assert.Check(t, is.Equal(bearerSubjectConfirmationMethod, sc.Method))
	assert.Assert(t, sc.SubjectConfirmationData != nil)
	assert.Check(t, is.Equal(req.Request.ID, sc.SubjectConfirmationData.InResponseTo))
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), sc.SubjectConfirmationData.Recipient))
}

// saml-core-2.0-os §3.2.1 (ID, Version, IssueInstant [Required]), §3.4.1
// and §3.4.1.1: the SP's AuthnRequest carries the required attributes and an
// Issuer; it names the ACS by AssertionConsumerServiceURL "typically
// accompanied by the ProtocolBinding attribute"; ForceAuthn is sent when
// configured; and since "if the requester wishes to permit the identity
// provider to establish a new identifier for the principal if none exists,
// it MUST include this element with the AllowCreate attribute set to
// \"true\"", NameIDPolicy has AllowCreate="true".
func TestSpecProtocol_3_4_1_SPAuthnRequestAttributes(t *testing.T) {
	test := idpcovNewTest(t)
	yes := true
	test.SP.ForceAuthn = &yes
	req, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)

	el := req.Element()
	assert.Check(t, el.SelectAttrValue("ID", "") != "")
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))
	assert.Check(t, is.Equal(TimeNow().Format(timeFormat), el.SelectAttrValue("IssueInstant", "")))
	assert.Check(t, is.Equal(test.IDP.SSOURL.String(), el.SelectAttrValue("Destination", "")))
	assert.Check(t, is.Equal(test.SP.MetadataURL.String(), el.FindElement("./Issuer").Text()))
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), el.SelectAttrValue("AssertionConsumerServiceURL", "")))
	assert.Check(t, is.Equal(HTTPPostBinding, el.SelectAttrValue("ProtocolBinding", "")))
	assert.Check(t, el.SelectAttr("AssertionConsumerServiceIndex") == nil)
	assert.Check(t, is.Equal("true", el.SelectAttrValue("ForceAuthn", "")))
	policy := el.FindElement("./NameIDPolicy")
	assert.Assert(t, policy != nil)
	assert.Check(t, is.Equal("true", policy.SelectAttrValue("AllowCreate", "")))

	// The IdP parses the same values back.
	buf, err := xml.Marshal(req)
	assert.NilError(t, err)
	var parsed AuthnRequest
	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Check(t, is.Equal(req.ID, parsed.ID))
	assert.Assert(t, parsed.ForceAuthn != nil)
	assert.Check(t, *parsed.ForceAuthn)
}

// saml-core-2.0-os §3.4.1.2: ProxyCount "A count of zero permits no
// proxying, while omitting this attribute expresses no such restriction."
// A ProxyCount of 0 is therefore serialized (not dropped as a zero value),
// and an unset one is omitted.
func TestSpecProtocol_3_4_1_2_ProxyCountZeroIsSerialized(t *testing.T) {
	zero := 0
	el := (&Scoping{ProxyCount: &zero, IDPList: &IDPList{IDPEntries: []IDPEntry{{ProviderID: "https://idp-a.example.com"}}}}).Element()
	assert.Check(t, is.Equal("0", el.SelectAttrValue("ProxyCount", "")))
	assert.Check(t, is.Equal("https://idp-a.example.com", el.FindElement("./IDPList/IDPEntry").SelectAttrValue("ProviderID", "")))

	el = (&Scoping{}).Element()
	assert.Check(t, el.SelectAttr("ProxyCount") == nil)

	var parsed AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(`<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">`+
		`<samlp:Scoping ProxyCount="0"/></samlp:AuthnRequest>`), &parsed))
	assert.Assert(t, parsed.Scoping != nil && parsed.Scoping.ProxyCount != nil)
	assert.Check(t, is.Equal(0, *parsed.Scoping.ProxyCount))
}

// saml-core-2.0-os §3.2.2.2: "The value of the topmost <StatusCode> element
// MUST be from the top-level list"; a second-level code is a <StatusCode>
// nested inside it. The Status element nests the codes that way and parses
// them back.
func TestSpecProtocol_3_2_2_2_StatusCodeNesting(t *testing.T) {
	status := Status{StatusCode: StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: StatusNoAuthnContext}}}
	el := status.Element()
	top := el.FindElement("./StatusCode")
	assert.Assert(t, top != nil)
	assert.Check(t, is.Equal(StatusResponder, top.SelectAttrValue("Value", "")))
	second := top.FindElement("./StatusCode")
	assert.Assert(t, second != nil)
	assert.Check(t, is.Equal(StatusNoAuthnContext, second.SelectAttrValue("Value", "")))
	assert.Check(t, is.Len(el.ChildElements(), 1))

	resp := LogoutResponse{ID: "id-1", Version: "2.0", IssueInstant: time.Date(2015, 12, 1, 1, 57, 9, 0, time.UTC), Status: status}
	buf, err := xml.Marshal(&resp)
	assert.NilError(t, err)
	var parsed LogoutResponse
	assert.NilError(t, xml.Unmarshal(buf, &parsed))
	assert.Check(t, is.Equal(StatusResponder, parsed.Status.StatusCode.Value))
	assert.Assert(t, parsed.Status.StatusCode.StatusCode != nil)
	assert.Check(t, is.Equal(StatusNoAuthnContext, parsed.Status.StatusCode.StatusCode.Value))
}

// saml-core-2.0-os §3.2.2.2 and §3.4.1.4: an error Response carries a
// top-level code (here Responder) and optionally a second-level one (here
// NoPassive). The SP rejects any Response whose top-level code is not
// Success and reports the top-level code in ErrBadStatus.
func TestSpecProtocol_3_2_2_2_SPRejectsNonSuccessTopLevelStatus(t *testing.T) {
	e := spcovSetup(t)
	for _, topLevel := range []string{StatusRequester, StatusResponder, StatusVersionMismatch} {
		t.Run(topLevel, func(t *testing.T) {
			r := e.response()
			r.Status = Status{StatusCode: StatusCode{Value: topLevel, StatusCode: &StatusCode{Value: StatusNoPassive}}}
			buf := spcovSerialize(t, e.idpSign(t, r.Element()))
			_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
			var badStatus ErrBadStatus
			assert.Assert(t, errors.As(err, &badStatus), "%v", err)
			assert.Check(t, is.Equal(topLevel, badStatus.Status))
		})
	}
}

// saml-core-2.0-os §3.2.1: "ID [Required] An identifier for the request",
// whose value the response's InResponseTo must match. The IdP rejects a
// (validly signed) LogoutRequest without an ID, so no session is ended.
func TestSpecProtocol_3_2_1_LogoutRequestIDRequired(t *testing.T) {
	test := specProtoSLOTest(t)
	req := test.logoutRequest()
	req.ID = ""
	w := test.serve(test.signedPostRequest(t, req))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	assert.Check(t, is.Equal(0, test.sessions.calls))
}

// saml-core-2.0-os §3.7.2: "The recipient of a <LogoutRequest> message MUST
// respond with a <LogoutResponse> message, of type StatusResponseType"; per
// §3.2.2 it has an ID, Version "2.0", IssueInstant and an InResponseTo equal
// to the request's ID, and per §3.7.3.2 a session authority that terminated
// the session responds with "a top-level status code of ...:Success".
func TestSpecProtocol_3_7_2_IdPLogoutResponseAttributes(t *testing.T) {
	test := specProtoSLOTest(t)
	req := test.logoutRequest()
	w := test.serve(test.redirectRequest(t, req))
	assert.Assert(t, is.Equal(http.StatusFound, w.Code))
	resp := decodeLogoutResponse(t, w)

	assert.Check(t, resp.ID != "")
	assert.Check(t, resp.ID != req.ID)
	assert.Check(t, is.Equal("2.0", resp.Version))
	assert.Check(t, resp.IssueInstant.Equal(TimeNow()))
	assert.Check(t, is.Equal(req.ID, resp.InResponseTo))
	assert.Assert(t, resp.Issuer != nil)
	assert.Check(t, is.Equal(test.IDP.MetadataURL.String(), resp.Issuer.Value))
	assert.Check(t, is.Equal(test.SP.SloURL.String(), resp.Destination))
	assert.Check(t, is.Equal(StatusSuccess, resp.Status.StatusCode.Value))
}

// saml-core-2.0-os §3.7.1 NotOnOrAfter, as amended by errata E92: "relying
// parties SHOULD allow for reasonable clock skew in the interpretation of
// both values." A LogoutRequest whose NotOnOrAfter passed less than
// MaxClockSkew ago is still accepted, by the IdP and by the SP; one that
// passed longer ago is rejected.
func TestSpecProtocol_3_7_1_NotOnOrAfterAllowsClockSkew(t *testing.T) {
	t.Run("IdP", func(t *testing.T) {
		test := specProtoSLOTest(t)
		req := test.logoutRequest()
		notOnOrAfter := TimeNow().Add(-MaxClockSkew / 2)
		req.NotOnOrAfter = &notOnOrAfter
		w := test.serve(test.redirectRequest(t, req))
		assert.Check(t, is.Equal(http.StatusFound, w.Code))
		assert.Check(t, is.Equal(1, test.sessions.calls))

		test = specProtoSLOTest(t)
		req = test.logoutRequest()
		notOnOrAfter = TimeNow().Add(-MaxClockSkew - time.Second)
		req.NotOnOrAfter = &notOnOrAfter
		w = test.serve(test.redirectRequest(t, req))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
	t.Run("SP", func(t *testing.T) {
		e := spcovSetup(t)
		request := func(notOnOrAfter time.Time) *LogoutRequest {
			return &LogoutRequest{
				ID: "id-logout-request", Version: "2.0", IssueInstant: spcovNow,
				NotOnOrAfter: &notOnOrAfter, Destination: e.sp.SloURL.String(),
				Issuer: &Issuer{Value: spcovIDPEntityID}, NameID: &NameID{Value: "alice@example.com"},
			}
		}
		assert.Check(t, e.sp.validateLogoutRequest(request(spcovNow.Add(-MaxClockSkew/2))))
		assert.Check(t, e.sp.validateLogoutRequest(request(spcovNow.Add(-MaxClockSkew-time.Second))) != nil)
	})
}

// saml-core-2.0-os §3.7.3.2: "the top-level status indicates the state of
// the logout operation only with respect to the session authority itself";
// incomplete propagation is reported with the second-level code PartialLogout
// under it. The SP therefore accepts a LogoutResponse with a top-level
// Success and a second-level PartialLogout, and rejects one whose top-level
// code is an error.
func TestSpecProtocol_3_7_3_2_SPAcceptsSuccessWithPartialLogout(t *testing.T) {
	e := spcovSetup(t)
	r := e.logoutResponse()
	r.Status.StatusCode.StatusCode = &StatusCode{Value: StatusPartialLogout}
	assert.Check(t, e.sp.validateLogoutResponse(r))

	r = e.logoutResponse()
	r.Status.StatusCode = StatusCode{Value: StatusResponder, StatusCode: &StatusCode{Value: StatusPartialLogout}}
	var badStatus ErrBadStatus
	assert.Check(t, errors.As(e.sp.validateLogoutResponse(r), &badStatus))
	assert.Check(t, is.Equal(StatusResponder, badStatus.Status))
}

// saml-core-2.0-os §3.7.1 and §3.2.1: the SP's LogoutRequest has the required
// ID, Version and IssueInstant, an Issuer, the principal's <saml:NameID>
// ("[Required]") and, when given, the <SessionIndex>, in schema order
// (Issuer, Signature, NameID, SessionIndex).
func TestSpecProtocol_3_7_1_SPLogoutRequestShape(t *testing.T) {
	test := specProtoSLOTest(t)
	req, err := test.SP.MakeLogoutRequest(test.IDP.LogoutURL.String(), sloTestNameID, WithSessionIndex(sloTestSessionIndex))
	assert.NilError(t, err)
	el := req.Element()
	assert.Check(t, el.SelectAttrValue("ID", "") != "")
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))
	assert.Check(t, el.SelectAttrValue("IssueInstant", "") != "")
	assert.Check(t, is.Equal(test.IDP.LogoutURL.String(), el.SelectAttrValue("Destination", "")))

	tags := make([]string, 0, len(el.ChildElements()))
	for _, child := range el.ChildElements() {
		tags = append(tags, child.Tag)
	}
	assert.Check(t, is.DeepEqual([]string{"Issuer", "Signature", "NameID", "SessionIndex"}, tags))
	assert.Check(t, is.Equal(sloTestNameID, el.FindElement("./NameID").Text()))
	assert.Check(t, is.Equal(sloTestSessionIndex, el.FindElement("./SessionIndex").Text()))
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:protocol", el.FindElement("./SessionIndex").NamespaceURI()))
}

// saml-core-2.0-os §3.7.2 and §3.2.2: the LogoutResponse the SP sends to
// answer the IdP's LogoutRequest has InResponseTo set to the request's ID,
// the required ID, Version and IssueInstant, and a top-level Success status.
func TestSpecProtocol_3_7_2_SPLogoutResponseAnswersRequest(t *testing.T) {
	e := spcovSetup(t)
	resp, err := e.sp.MakeLogoutResponse("https://idp.example.com/slo/redirect", "id-idp-logout-request")
	assert.NilError(t, err)
	el := resp.Element()
	assert.Check(t, el.SelectAttrValue("ID", "") != "")
	assert.Check(t, is.Equal("id-idp-logout-request", el.SelectAttrValue("InResponseTo", "")))
	assert.Check(t, is.Equal("2.0", el.SelectAttrValue("Version", "")))
	assert.Check(t, is.Equal(spcovNow.Format(timeFormat), el.SelectAttrValue("IssueInstant", "")))
	assert.Check(t, is.Equal(StatusSuccess, el.FindElement("./Status/StatusCode").SelectAttrValue("Value", "")))
}
