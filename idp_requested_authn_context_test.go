package saml

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const (
	racPPT          = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport"
	racPassword     = "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" //nolint:gosec // G101: an authentication context class URI, not a credential
	racX509         = "urn:oasis:names:tc:SAML:2.0:ac:classes:X509"
	racSmartcardPKI = "urn:oasis:names:tc:SAML:2.0:ac:classes:SmartcardPKI"
	racUnspecified  = "urn:oasis:names:tc:SAML:2.0:ac:classes:unspecified"
	racCustomMFA    = "https://refeds.org/profile/mfa"
)

// racServeSSO sends an AuthnRequest from test.SP carrying requested to
// ServeSSO, with a session authenticated with achieved, and returns the
// recorded HTTP response. OnError must not be called.
func racServeSSO(t *testing.T, test *IdentityProviderTest, requested *RequestedAuthnContext, achieved string) *httptest.ResponseRecorder {
	t.Helper()
	test.SP.RequestedAuthnContext = requested
	test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: func(_ http.ResponseWriter, _ *http.Request, _ *IdpAuthnRequest) *Session {
		return &Session{ID: "f00df00df00d", UserName: "alice", AuthnContextClassRef: achieved}
	}}
	test.IDP.OnError = func(w http.ResponseWriter, r *http.Request, status int, err error) {
		t.Errorf("OnError called with %d: %v", status, err)
		test.IDP.DefaultOnError(w, r, status, err)
	}
	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	return w
}

// racAssertedClass returns the top-level status code of the Response posted
// in w and, for a Success, the AuthnContextClassRef of the assertion as
// test.SP parses it (the assertion is encrypted to the SP).
func racAssertedClass(t *testing.T, test *IdentityProviderTest, w *httptest.ResponseRecorder) (status, class string) {
	t.Helper()
	el, _, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	status = el.FindElement("./Status/StatusCode").SelectAttrValue("Value", "")
	if status != StatusSuccess {
		return status, ""
	}
	assertion, err := test.SP.ParseResponse(postForm(t, w.Body.Bytes()), []string{el.SelectAttrValue("InResponseTo", "")})
	if err != nil {
		t.Fatalf("SP rejected the response: %v", spcovPrivateErr(t, err))
	}
	assert.Assert(t, is.Len(assertion.AuthnStatements, 1))
	return status, assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value
}

// The issue's reproduction: without enforcement a request for X509 is still
// answered with Success and PasswordProtectedTransport (unchanged
// behaviour); with it, the IdP refuses with Responder/NoAuthnContext.
func TestIDPRequestedAuthnContextExactUnsatisfiable(t *testing.T) {
	requested := &RequestedAuthnContext{Comparison: "exact", AuthnContextClassRefs: []string{racX509}}

	t.Run("default", func(t *testing.T) {
		test := idpErrNewTest(t)
		status, class := racAssertedClass(t, test, racServeSSO(t, test, requested, ""))
		assert.Check(t, is.Equal(StatusSuccess, status))
		assert.Check(t, is.Equal(racPPT, class))
	})

	t.Run("enforced", func(t *testing.T) {
		test := idpErrNewTest(t)
		test.IDP.EnforceRequestedAuthnContext = true
		w := racServeSSO(t, test, requested, "")
		el, _, _ := idpErrResponseFromForm(t, w.Body.Bytes())
		requestID := el.SelectAttrValue("InResponseTo", "")
		idpErrCheckErrorResponse(t, test, el, requestID, StatusResponder, StatusNoAuthnContext,
			"the requested authentication context cannot be satisfied")
		idpErrCheckSPRejects(t, test, w.Body.Bytes(), []string{requestID}, StatusResponder)
	})
}

// The class in the Session is asserted, enforced or not, and an exact
// request for it succeeds.
func TestIDPRequestedAuthnContextSessionClassAsserted(t *testing.T) {
	for _, enforce := range []bool{false, true} {
		test := idpErrNewTest(t)
		test.IDP.EnforceRequestedAuthnContext = enforce
		requested := &RequestedAuthnContext{AuthnContextClassRefs: []string{racSmartcardPKI, racX509}}
		status, class := racAssertedClass(t, test, racServeSSO(t, test, requested, racX509))
		assert.Check(t, is.Equal(StatusSuccess, status), "enforce=%v", enforce)
		assert.Check(t, is.Equal(racX509, class), "enforce=%v", enforce)
	}
}

// Without a RequestedAuthnContext, an enforcing IdP asserts the session's
// class, or PasswordProtectedTransport when the session names none.
func TestIDPRequestedAuthnContextNoneRequested(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	status, class := racAssertedClass(t, test, racServeSSO(t, test, nil, ""))
	assert.Check(t, is.Equal(StatusSuccess, status))
	assert.Check(t, is.Equal(racPPT, class))
}

func TestIDPRequestedAuthnContextMinimumThroughServeSSO(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	requested := &RequestedAuthnContext{Comparison: "minimum", AuthnContextClassRefs: []string{racPPT}}
	status, class := racAssertedClass(t, test, racServeSSO(t, test, requested, racSmartcardPKI))
	assert.Check(t, is.Equal(StatusSuccess, status))
	assert.Check(t, is.Equal(racSmartcardPKI, class))

	test = idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	status, class = racAssertedClass(t, test, racServeSSO(t, test, requested, racPassword))
	assert.Check(t, is.Equal(StatusResponder, status))
	assert.Check(t, is.Equal("", class))
}

func TestIDPRequestedAuthnContextComparisons(t *testing.T) {
	type tc struct {
		comparison string
		requested  []string
		achieved   string
		want       bool
	}
	cases := []tc{
		{"", []string{racPPT}, racPPT, true},
		{"", []string{racX509}, racPPT, false},
		{"exact", []string{racX509, racPPT}, racPPT, true},
		{"exact", []string{racX509}, racSmartcardPKI, false}, // stronger is not exact

		{"minimum", []string{racPPT}, racPPT, true},
		{"minimum", []string{racPPT}, racX509, true},
		{"minimum", []string{racX509}, racPPT, false},
		{"minimum", []string{racX509, racPassword}, racPPT, true}, // at least one
		{"minimum", []string{racUnspecified}, racX509, false},     // unranked
		{"minimum", []string{racCustomMFA}, racCustomMFA, true},   // identical

		{"maximum", []string{racX509}, racPPT, true},
		{"maximum", []string{racX509}, racX509, true},
		{"maximum", []string{racPPT}, racX509, false},
		{"maximum", []string{racPassword}, racUnspecified, false},

		{"better", []string{racPPT}, racX509, true},
		{"better", []string{racPPT}, racPPT, false},
		{"better", []string{racX509}, racPPT, false},
		{"better", []string{racX509, racPassword}, racPPT, true},
		{"better", []string{racCustomMFA}, racSmartcardPKI, false}, // unranked
	}
	strengths := DefaultAuthnContextClassStrengths()
	for _, c := range cases {
		ok, known := authnContextSatisfies(c.comparison, c.requested, c.achieved, strengths)
		assert.Check(t, known)
		assert.Check(t, is.Equal(c.want, ok), "%q %v %q", c.comparison, c.requested, c.achieved)
	}
	_, known := authnContextSatisfies("stronger", []string{racPPT}, racPPT, strengths)
	assert.Check(t, !known)
}

func TestIDPRequestedAuthnContextCustomStrengths(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	strengths := DefaultAuthnContextClassStrengths()
	strengths[racCustomMFA] = 10
	test.IDP.AuthnContextClassStrengths = strengths
	requested := &RequestedAuthnContext{Comparison: "better", AuthnContextClassRefs: []string{racX509}}
	status, class := racAssertedClass(t, test, racServeSSO(t, test, requested, racCustomMFA))
	assert.Check(t, is.Equal(StatusSuccess, status))
	assert.Check(t, is.Equal(racCustomMFA, class))

	// The default ranking is a fresh copy each time.
	assert.Check(t, is.Equal(0, DefaultAuthnContextClassStrengths()[racCustomMFA]))
}

func TestIDPRequestedAuthnContextUnknownComparison(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	req := idpErrValidRequest(t, test)
	req.Request.RequestedAuthnContext = &RequestedAuthnContext{Comparison: "stronger", AuthnContextClassRefs: []string{racPPT}}
	err := DefaultAssertionMaker{}.MakeAssertion(req, &Session{NameID: "alice"})
	statusErr, ok := err.(*StatusError)
	assert.Assert(t, ok, "%v", err)
	assert.Check(t, is.Equal(StatusRequester, statusErr.TopLevel))
	assert.Check(t, is.Equal("", statusErr.SecondLevel))
}

// A RequestedAuthnContext naming no class (only declarations, which are not
// parsed) is not evaluated.
func TestIDPRequestedAuthnContextNoClassRefs(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceRequestedAuthnContext = true
	req := idpErrValidRequest(t, test)
	req.Request.RequestedAuthnContext = &RequestedAuthnContext{Comparison: "exact"}
	assert.NilError(t, DefaultAssertionMaker{}.MakeAssertion(req, &Session{NameID: "alice"}))
	assert.Check(t, is.Equal(racPPT, req.Assertion.AuthnStatements[0].AuthnContext.AuthnContextClassRef.Value))
}
