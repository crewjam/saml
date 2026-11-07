package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const (
	reqSubjEmailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	reqSubjHoKMethod   = "urn:oasis:names:tc:SAML:2.0:cm:holder-of-key"

	reqSubjPersistentFormat = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
)

// reqSubjNewTest returns an IdP test whose session is alice@example.com,
// with the emailAddress NameID Format.
func reqSubjNewTest(t *testing.T) *IdentityProviderTest {
	t.Helper()
	return reqSubjNewTestFormat(t, reqSubjEmailFormat)
}

// reqSubjNewTestFormat is reqSubjNewTest with the given NameID Format.
func reqSubjNewTestFormat(t *testing.T, format string) *IdentityProviderTest {
	t.Helper()
	test := idpErrNewTest(t)
	test.IDP.SessionProvider = &mockSessionProvider{
		GetSessionFunc: func(http.ResponseWriter, *http.Request, *IdpAuthnRequest) *Session {
			return &Session{
				ID:           "f00df00df00d",
				UserName:     "alice",
				NameID:       "alice@example.com",
				NameIDFormat: format,
			}
		},
	}
	return test
}

// reqSubjServe sends an AuthnRequest from test.SP with the given Subject to
// ServeSSO with the HTTP-Redirect binding, and returns the request ID and
// the recorded response.
func reqSubjServe(t *testing.T, test *IdentityProviderTest, subject *Subject) (string, *httptest.ResponseRecorder) {
	t.Helper()
	authnReq, err := test.SP.MakeAuthenticationRequest(
		test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
	assert.NilError(t, err)
	authnReq.Subject = subject
	u, err := authnReq.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	r, err := http.NewRequest("GET", u.String(), nil)
	assert.NilError(t, err)

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, r)
	assert.Equal(t, http.StatusOK, w.Code, w.Body.String())
	return authnReq.ID, w
}

// reqSubjCheckSuccess checks that the IdP answered with an assertion about
// alice@example.com that the SP accepts.
func reqSubjCheckSuccess(t *testing.T, test *IdentityProviderTest, id string, w *httptest.ResponseRecorder) {
	t.Helper()
	assertion, err := test.SP.ParseResponse(postForm(t, w.Body.Bytes()), []string{id})
	assert.NilError(t, err)
	assert.Assert(t, assertion.Subject != nil && assertion.Subject.NameID != nil)
	assert.Check(t, is.Equal("alice@example.com", assertion.Subject.NameID.Value))
}

// reqSubjCheckRefused checks that the IdP answered with an error Response
// with no assertion and the given status codes.
func reqSubjCheckRefused(t *testing.T, test *IdentityProviderTest, id string, w *httptest.ResponseRecorder, topLevel, secondLevel, message string) {
	t.Helper()
	el, action, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(test.SP.AcsURL.String(), action))
	idpErrCheckErrorResponse(t, test, el, id, topLevel, secondLevel, message)
	idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{id}, topLevel)
}

func reqSubjNameID(value string) *Subject {
	return &Subject{NameID: &NameID{Value: value}}
}

func TestIDPRequestSubjectAbsentIsUnchanged(t *testing.T) {
	test := reqSubjNewTest(t)
	id, w := reqSubjServe(t, test, nil)
	reqSubjCheckSuccess(t, test, id, w)
}

func TestIDPRequestSubjectMatchingNameID(t *testing.T) {
	test := reqSubjNewTest(t)
	idpEntityID := test.IDP.Metadata().EntityID
	spEntityID := test.SP.Metadata().EntityID

	// NameQualifier and SPNameQualifier are only emitted for the persistent
	// and transient formats, so the cases with qualifiers use a persistent
	// session.
	for name, tc := range map[string]struct {
		sessionFormat string
		nameID        *NameID
	}{
		"value only":            {reqSubjEmailFormat, &NameID{Value: "alice@example.com"}},
		"format":                {reqSubjEmailFormat, &NameID{Value: "alice@example.com", Format: reqSubjEmailFormat}},
		"unspecified format":    {reqSubjEmailFormat, &NameID{Value: "alice@example.com", Format: nameIDFormatUnspecified}},
		"qualifiers":            {reqSubjPersistentFormat, &NameID{Value: "alice@example.com", NameQualifier: idpEntityID, SPNameQualifier: spEntityID}},
		"format and qualifiers": {reqSubjPersistentFormat, &NameID{Value: "alice@example.com", Format: reqSubjPersistentFormat, NameQualifier: idpEntityID, SPNameQualifier: spEntityID}},
	} {
		nameID := tc.nameID
		t.Run(name, func(t *testing.T) {
			test := reqSubjNewTestFormat(t, tc.sessionFormat)
			id, w := reqSubjServe(t, test, &Subject{NameID: nameID})
			reqSubjCheckSuccess(t, test, id, w)
		})
	}
}

func TestIDPRequestSubjectBearerConfirmationMatches(t *testing.T) {
	test := reqSubjNewTest(t)
	subject := reqSubjNameID("alice@example.com")
	subject.SubjectConfirmations = []SubjectConfirmation{{Method: bearerSubjectConfirmationMethod}}
	id, w := reqSubjServe(t, test, subject)
	reqSubjCheckSuccess(t, test, id, w)
}

func TestIDPRequestSubjectMismatchIsRefused(t *testing.T) {
	for name, nameID := range map[string]*NameID{
		"other principal":        {Value: "bob@example.com"},
		"case differs":           {Value: "Alice@example.com"},
		"other format":           {Value: "alice@example.com", Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"},
		"other name qualifier":   {Value: "alice@example.com", NameQualifier: "https://other-idp.example.com/metadata"},
		"other SP qualifier":     {Value: "alice@example.com", SPNameQualifier: "https://other-sp.example.com/metadata"},
		"SPProvidedID not given": {Value: "alice@example.com", SPProvidedID: "alice-at-sp"},
	} {
		t.Run(name, func(t *testing.T) {
			test := reqSubjNewTest(t)
			id, w := reqSubjServe(t, test, &Subject{NameID: nameID})
			reqSubjCheckRefused(t, test, id, w, StatusRequester, StatusUnknownPrincipal,
				"the authenticated principal is not the subject of the request")
		})
	}
}

func TestIDPRequestSubjectConfirmationOnlyIsRefused(t *testing.T) {
	test := reqSubjNewTest(t)
	subject := &Subject{SubjectConfirmations: []SubjectConfirmation{{Method: bearerSubjectConfirmationMethod}}}
	id, w := reqSubjServe(t, test, subject)
	reqSubjCheckRefused(t, test, id, w, StatusRequester, StatusUnknownPrincipal,
		"the request subject has no identifier")
}

func TestIDPRequestSubjectUncomparableIdentifierIsRefused(t *testing.T) {
	baseID := etree.NewElement("saml:BaseID")
	baseID.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	baseID.CreateAttr("xsi:type", "xs:string")

	encryptedID := etree.NewElement("saml:EncryptedID")
	encData := encryptedID.CreateElement("xenc:EncryptedData")
	encData.CreateAttr("xmlns:xenc", "http://www.w3.org/2001/04/xmlenc#")
	encData.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").SetText("AAAA")

	for name, subject := range map[string]*Subject{
		"BaseID":      {BaseID: baseID},
		"EncryptedID": {EncryptedID: encryptedID},
	} {
		t.Run(name, func(t *testing.T) {
			test := reqSubjNewTest(t)
			id, w := reqSubjServe(t, test, subject)
			reqSubjCheckRefused(t, test, id, w, StatusResponder, StatusUnknownPrincipal,
				"the request subject identifier is not supported")
		})
	}
}

func TestIDPRequestSubjectUnsupportedConfirmationIsRefused(t *testing.T) {
	test := reqSubjNewTest(t)
	subject := reqSubjNameID("alice@example.com")
	subject.SubjectConfirmations = []SubjectConfirmation{{Method: reqSubjHoKMethod}}
	id, w := reqSubjServe(t, test, subject)
	reqSubjCheckRefused(t, test, id, w, StatusResponder, StatusRequestUnsupported,
		"the requested subject confirmation method is not supported")
}

// The check applies to the assertion a custom AssertionMaker makes, too.
func TestIDPRequestSubjectCustomAssertionMaker(t *testing.T) {
	test := reqSubjNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(req *IdpAuthnRequest, session *Session) error {
		if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
			return err
		}
		req.Assertion.Subject.NameID.Value = "mallory@example.com"
		return nil
	})
	id, w := reqSubjServe(t, test, reqSubjNameID("alice@example.com"))
	reqSubjCheckRefused(t, test, id, w, StatusRequester, StatusUnknownPrincipal,
		"the authenticated principal is not the subject of the request")
}

// An assertion whose Subject has no NameID cannot be matched.
func TestIDPRequestSubjectAssertionWithoutNameID(t *testing.T) {
	test := reqSubjNewTest(t)
	test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(req *IdpAuthnRequest, session *Session) error {
		if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
			return err
		}
		req.Assertion.Subject.NameID = nil
		return nil
	})
	id, w := reqSubjServe(t, test, reqSubjNameID("alice@example.com"))
	reqSubjCheckRefused(t, test, id, w, StatusResponder, StatusUnknownPrincipal,
		"the subject of the request cannot be matched")
}

// The reproduction from the issue: a handler driving the flow itself can
// use CheckRequestSubject.
func TestIDPCheckRequestSubject(t *testing.T) {
	test := reqSubjNewTest(t)
	req := idpcovRequest(t, test)

	// No Subject and no assertion: nothing to check.
	assert.NilError(t, req.CheckRequestSubject())
	req.Request.Subject = reqSubjNameID("bob@example.com")
	assert.NilError(t, req.CheckRequestSubject())

	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{NameID: "alice@example.com"}))
	err := req.CheckRequestSubject()
	var statusErr *StatusError
	assert.Assert(t, errors.As(err, &statusErr), "got %v", err)
	assert.Check(t, is.Equal(StatusRequester, statusErr.TopLevel))
	assert.Check(t, is.Equal(StatusUnknownPrincipal, statusErr.SecondLevel))

	req.Request.Subject = reqSubjNameID("alice@example.com")
	assert.NilError(t, req.CheckRequestSubject())
	req.Request.Subject = nil
	assert.NilError(t, req.CheckRequestSubject())
}
