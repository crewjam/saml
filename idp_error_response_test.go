package saml

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// idpErrNewTest returns an IdP test whose SP trusts the IdP's (expired) test
// certificate, so that the SP can parse what the IdP sends.
func idpErrNewTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	test := idpcovNewTest(t)
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
	test.SP.IgnoreCertificateExpiry = true
	return test
}

// idpErrValidRequest returns a validated IdpAuthnRequest from test.SP sent
// with the HTTP-Redirect binding.
func idpErrValidRequest(t *testing.T, test *IdentityProviderTest) *IdpAuthnRequest {
	t.Helper()
	req, err := NewIdpAuthnRequest(&test.IDP, idpcovSSORequest(t, test))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	return req
}

// idpErrResponseFromForm returns the Response element posted by the HTML
// form in body, and the form's action and fields.
func idpErrResponseFromForm(t *testing.T, body []byte) (*etree.Element, string, map[string][]string) {
	t.Helper()
	action, fields := formFields(t, body)
	buf, err := base64.StdEncoding.DecodeString(fields.Get("SAMLResponse"))
	assert.NilError(t, err)
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes(buf))
	return doc.Root(), action, fields
}

// idpErrCheckErrorResponse checks that el is a signed Response from the IdP
// with the given status codes and no assertion.
func idpErrCheckErrorResponse(t *testing.T, test *IdentityProviderTest, el *etree.Element, inResponseTo, topLevel, secondLevel, message string) {
	t.Helper()
	assert.Check(t, is.Equal("Response", el.Tag))
	assert.Check(t, is.Equal(inResponseTo, el.SelectAttrValue("InResponseTo", "<none>")))
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), el.SelectAttrValue("Destination", "")))
	assert.Check(t, is.Equal(test.IDP.MetadataURL.String(), el.FindElement("./Issuer").Text()))
	assert.Check(t, el.FindElement("./Signature") != nil, "response is not signed")
	assert.Check(t, el.FindElement("./Assertion") == nil)
	assert.Check(t, el.FindElement("./EncryptedAssertion") == nil)

	code := el.FindElement("./Status/StatusCode")
	assert.Assert(t, code != nil)
	assert.Check(t, is.Equal(topLevel, code.SelectAttrValue("Value", "")))
	nested := code.FindElement("./StatusCode")
	if secondLevel == "" {
		assert.Check(t, nested == nil)
	} else if assert.Check(t, nested != nil) {
		assert.Check(t, is.Equal(secondLevel, nested.SelectAttrValue("Value", "")))
	}
	msg := el.FindElement("./Status/StatusMessage")
	if message == "" {
		assert.Check(t, msg == nil)
	} else if assert.Check(t, msg != nil) {
		assert.Check(t, is.Equal(message, msg.Text()))
	}
}

// idpErrCheckSPRejects checks that the SP parsing the form in body for
// requestIDs reports ErrBadStatus with topLevel.
func idpErrCheckSPRejects(t *testing.T, test *IdentityProviderTest, body []byte, requestIDs []string, topLevel string) {
	t.Helper()
	_, err := test.SP.ParseResponse(postForm(t, body), requestIDs)
	var badStatus ErrBadStatus
	if !errors.As(err, &badStatus) {
		t.Fatalf("expected ErrBadStatus, got %v", spcovPrivateErr(t, err))
	}
	assert.Check(t, is.Equal(topLevel, badStatus.Status))
}

func TestIDPMakeErrorResponse(t *testing.T) {
	test := idpErrNewTest(t)
	req := idpErrValidRequest(t, test)

	assert.NilError(t, req.MakeErrorResponse(StatusResponder, StatusNoPassive, "cannot authenticate passively"))
	assert.Check(t, req.Assertion == nil)
	assert.Check(t, req.AssertionEl == nil)
	idpErrCheckErrorResponse(t, test, req.ResponseEl, req.Request.ID, StatusResponder, StatusNoPassive, "cannot authenticate passively")

	// The Response unmarshals into the package's Response type.
	var response Response
	assert.NilError(t, unmarshalEtreeHack(req.ResponseEl.Copy(), &response))
	assert.Check(t, is.Equal(StatusResponder, response.Status.StatusCode.Value))
	assert.Check(t, response.Assertion == nil)

	// It is posted to the ACS with the RelayState, like a success Response.
	w := httptest.NewRecorder()
	assert.NilError(t, req.WriteResponse(w))
	_, action, fields := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
	assert.Check(t, is.DeepEqual([]string{"relay"}, fields["RelayState"]))

	idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{req.Request.ID}, StatusResponder)
}

func TestIDPMakeErrorResponseWithoutSecondLevelOrMessage(t *testing.T) {
	test := idpErrNewTest(t)
	req := idpErrValidRequest(t, test)
	assert.NilError(t, req.MakeErrorResponse(StatusRequester, "", ""))
	idpErrCheckErrorResponse(t, test, req.ResponseEl, req.Request.ID, StatusRequester, "", "")
}

func TestIDPMakeErrorResponseReplacesAssertion(t *testing.T) {
	test := idpErrNewTest(t)
	req := idpErrValidRequest(t, test)
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{ID: "s", UserName: "alice"}))
	assert.NilError(t, req.MakeAssertionEl())

	assert.NilError(t, req.MakeErrorResponse(StatusResponder, StatusRequestDenied, ""))
	assert.Check(t, req.Assertion == nil)
	idpErrCheckErrorResponse(t, test, req.ResponseEl, req.Request.ID, StatusResponder, StatusRequestDenied, "")
}

func TestIDPMakeErrorResponseErrors(t *testing.T) {
	test := idpErrNewTest(t)

	for _, top := range []string{"", StatusSuccess, StatusNoPassive, "urn:example:status"} {
		req := idpErrValidRequest(t, test)
		assert.Check(t, req.MakeErrorResponse(top, "", "") != nil, "top-level %q", top)
		assert.Check(t, req.ResponseEl == nil)
	}

	req := idpErrValidRequest(t, test)
	req.ACSEndpoint = nil
	assert.ErrorContains(t, req.MakeErrorResponse(StatusResponder, "", ""), "no assertion consumer service")

	req = idpErrValidRequest(t, test)
	test.IDP.SignatureMethod = "urn:idperr:bogus-signature-method"
	assert.Check(t, req.MakeErrorResponse(StatusResponder, "", "") != nil)
}

func TestIDPMakeErrorResponseSimpleSign(t *testing.T) {
	test := newSimpleSignIDPTest(t)
	form, err := test.SP.MakeSimpleSignAuthenticationRequest("rs")
	assert.NilError(t, err)
	req, err := NewIdpAuthnRequest(&test.IDP, postForm(t, form))
	assert.NilError(t, err)
	assert.NilError(t, req.Validate())
	req.ACSEndpoint = &IndexedEndpoint{Binding: HTTPPostSimpleSignBinding, Location: test.SP.AcsURL.String()}

	assert.NilError(t, req.MakeErrorResponse(StatusResponder, StatusNoAuthnContext, ""))
	w := httptest.NewRecorder()
	assert.NilError(t, DefaultResponseWriter{}.WriteResponse(w, req))
	el, _, fields := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, len(fields["Signature"]) == 1, "not a SimpleSign form: %s", w.Body.String())
	idpErrCheckErrorResponse(t, test, el, req.Request.ID, StatusResponder, StatusNoAuthnContext, "")
	idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{req.Request.ID}, StatusResponder)
}

func TestIDPStatusErrorMessage(t *testing.T) {
	assert.Check(t, is.Equal("saml: status "+StatusResponder, (&StatusError{TopLevel: StatusResponder}).Error()))
	assert.Check(t, is.Equal("saml: status "+StatusResponder+" ("+StatusNoPassive+"): no UI",
		(&StatusError{TopLevel: StatusResponder, SecondLevel: StatusNoPassive, Message: "no UI"}).Error()))
}

func TestIDPServeSSOAssertionMakerStatusError(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return fmt.Errorf("checking the context: %w", &StatusError{TopLevel: StatusResponder, SecondLevel: StatusNoAuthnContext, Message: "MFA is not available"})
	})
	var onErrorCalled bool
	test.IDP.OnError = func(w http.ResponseWriter, r *http.Request, status int, err error) {
		onErrorCalled = true
		test.IDP.DefaultOnError(w, r, status, err)
	}

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	assert.Check(t, !onErrorCalled)

	el, action, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
	requestID := el.SelectAttrValue("InResponseTo", "")
	assert.Check(t, requestID != "")
	idpErrCheckErrorResponse(t, test, el, requestID, StatusResponder, StatusNoAuthnContext, "MFA is not available")
	idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{requestID}, StatusResponder)
}

func TestIDPServeSSOAssertionMakerPlainErrorStill500(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return errors.New("database on fire")
	})
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestIDPServeSSOStatusErrorCannotSign(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return &StatusError{TopLevel: StatusResponder}
	})
	test.IDP.SignatureMethod = "urn:idperr:bogus-signature-method"
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Check(t, is.Equal(http.StatusInternalServerError, w.Code))
}

func TestIDPServeIDPInitiatedAssertionMakerStatusError(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error {
		return &StatusError{TopLevel: StatusResponder, SecondLevel: StatusRequestDenied}
	})
	w := httptest.NewRecorder()
	r := httptest.NewRequest("GET", "https://idp.example.com/services/sp/whoami", nil)
	test.IDP.ServeIDPInitiated(w, r, test.SP.MetadataURL.String(), "relay")
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())

	el, action, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
	idpErrCheckErrorResponse(t, test, el, "<none>", StatusResponder, StatusRequestDenied, "")
}

func TestIDPSendErrorResponseNil(t *testing.T) {
	test := idpErrNewTest(t)
	req := idpErrValidRequest(t, test)
	assert.Check(t, test.IDP.SendErrorResponse(httptest.NewRecorder(), req, nil) != nil)
}

func TestIDPSendErrorResponseUsesResponseWriter(t *testing.T) {
	test := idpErrNewTest(t)
	var seen *IdpAuthnRequest
	test.IDP.ResponseWriter = idpErrResponseWriterFunc(func(w http.ResponseWriter, req *IdpAuthnRequest) error {
		seen = req
		return req.WriteResponse(w)
	})
	req := idpErrValidRequest(t, test)
	w := httptest.NewRecorder()
	assert.NilError(t, test.IDP.SendErrorResponse(w, req, &StatusError{TopLevel: StatusResponder, SecondLevel: StatusNoPassive}))
	assert.Check(t, seen == req)
	assert.Check(t, seen.Assertion == nil)
	idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{req.Request.ID}, StatusResponder)
}

type idpErrResponseWriterFunc func(w http.ResponseWriter, req *IdpAuthnRequest) error

func (f idpErrResponseWriterFunc) WriteResponse(w http.ResponseWriter, req *IdpAuthnRequest) error {
	return f(w, req)
}

// idpErrLater moves TimeNow past MaxIssueDelay, so that requests made before
// it are expired.
func idpErrLater(t *testing.T) {
	t.Helper()
	before := TimeNow()
	TimeNow = func() time.Time { return before.Add(MaxIssueDelay + time.Minute) }
}

func TestIDPServeSSOExpiredRequest(t *testing.T) {
	t.Run("HTTP 400 by default", func(t *testing.T) {
		test := idpErrNewTest(t)
		r := idpcovSSORequest(t, test)
		idpErrLater(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("error Response with SendErrorResponses", func(t *testing.T) {
		test := idpErrNewTest(t)
		test.IDP.SendErrorResponses = true
		sessionAsked := false
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: func(w http.ResponseWriter, r *http.Request, req *IdpAuthnRequest) *Session {
			sessionAsked = true
			return idpcovAliceSession(w, r, req)
		}}
		r := idpcovSSORequest(t, test)
		idpErrLater(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, r)
		assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
		assert.Check(t, !sessionAsked)

		el, action, fields := idpErrResponseFromForm(t, w.Body.Bytes())
		assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
		assert.Check(t, is.DeepEqual([]string{"relay"}, fields["RelayState"]))
		requestID := el.SelectAttrValue("InResponseTo", "")
		assert.Check(t, requestID != "")
		idpErrCheckErrorResponse(t, test, el, requestID, StatusRequester, "", "the request has expired")
		idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{requestID}, StatusRequester)
	})

	t.Run("HTTP 400 for an unknown service provider", func(t *testing.T) {
		test := idpErrNewTest(t)
		test.IDP.SendErrorResponses = true
		authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		authnReq.Issuer.Value = "https://unknown.example.com/saml2/metadata"
		u, err := authnReq.Redirect("relay", &test.SP)
		assert.NilError(t, err)
		idpErrLater(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest("GET", u.String(), nil))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	t.Run("HTTP 400 for an ACS not in the metadata", func(t *testing.T) {
		test := idpErrNewTest(t)
		test.IDP.SendErrorResponses = true
		authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		authnReq.AssertionConsumerServiceURL = "https://evil.example.com/acs"
		u, err := authnReq.Redirect("relay", &test.SP)
		assert.NilError(t, err)
		idpErrLater(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest("GET", u.String(), nil))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})
}

func TestIDPServeSSOVersionMismatch(t *testing.T) {
	request := func(t *testing.T, test *IdentityProviderTest, version string) *http.Request {
		t.Helper()
		authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		authnReq.Version = version
		u, err := authnReq.Redirect("relay", &test.SP)
		assert.NilError(t, err)
		return httptest.NewRequest("GET", u.String(), nil)
	}

	t.Run("HTTP 400 by default", func(t *testing.T) {
		test := idpErrNewTest(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, request(t, test, "3.0"))
		assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
	})

	for _, tc := range []struct{ version, secondLevel string }{
		{"3.0", StatusRequestVersionTooHigh},
		{"1.1", StatusRequestVersionTooLow},
		{"2.1", ""},
		{"x", ""},
	} {
		t.Run("SendErrorResponses version "+tc.version, func(t *testing.T) {
			test := idpErrNewTest(t)
			test.IDP.SendErrorResponses = true
			w := httptest.NewRecorder()
			test.IDP.ServeSSO(w, request(t, test, tc.version))
			assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
			el, _, _ := idpErrResponseFromForm(t, w.Body.Bytes())
			requestID := el.SelectAttrValue("InResponseTo", "")
			idpErrCheckErrorResponse(t, test, el, requestID, StatusVersionMismatch, tc.secondLevel, "SAML version 2.0 is required")
			idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{requestID}, StatusVersionMismatch)
		})
	}
}

func TestIDPServeSSOSendErrorResponsesKeeps400(t *testing.T) {
	// Failures other than expiry and version still get HTTP 400.
	test := idpErrNewTest(t)
	test.IDP.SendErrorResponses = true
	authnReq, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	authnReq.Destination = "https://elsewhere.example.com/sso"
	u, err := authnReq.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, httptest.NewRequest("GET", u.String(), nil))
	assert.Check(t, is.Equal(http.StatusBadRequest, w.Code))
}
