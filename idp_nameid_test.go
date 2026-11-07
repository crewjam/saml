package saml

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// Tests for the NameID DefaultAssertionMaker issues (issue #784).

const (
	nameidTestIDP = "https://idp.example.com/saml/metadata"
	nameidTestSP  = "https://sp.example.com/saml2/metadata"
)

// nameidRequest returns a request for MakeAssertion whose AuthnRequest has
// the given NameIDPolicy (nil for none).
func nameidRequest(t *testing.T, test *IdentityProviderTest, policy *NameIDPolicy) *IdpAuthnRequest {
	t.Helper()
	req := idpcovRequest(t, test)
	req.Request.NameIDPolicy = policy
	return req
}

func nameidPolicy(format, spNameQualifier string) *NameIDPolicy {
	policy := &NameIDPolicy{}
	if format != "" {
		policy.Format = &format
	}
	if spNameQualifier != "" {
		policy.SPNameQualifier = &spNameQualifier
	}
	return policy
}

func nameidMake(t *testing.T, req *IdpAuthnRequest, session *Session) (*NameID, error) {
	t.Helper()
	if err := (DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return nil, err
	}
	assert.Assert(t, req.Assertion != nil && req.Assertion.Subject != nil)
	return req.Assertion.Subject.NameID, nil
}

// TestNameIDQualifiersOnlyForPersistentAndTransient checks that
// NameQualifier and SPNameQualifier are only emitted for the formats that
// define them (saml-core §2.2.2), and that an explicit session format is
// used as is.
func TestNameIDQualifiersOnlyForPersistentAndTransient(t *testing.T) {
	test := idpcovNewTest(t)
	qualified := []string{"", string(TransientNameIDFormat), string(PersistentNameIDFormat)}
	for _, format := range qualified {
		t.Run("qualified "+format, func(t *testing.T) {
			nameID, err := nameidMake(t, nameidRequest(t, test, nil), &Session{ID: "x", NameID: "abc123", NameIDFormat: format})
			assert.NilError(t, err)
			want := format
			if want == "" {
				want = string(TransientNameIDFormat)
			}
			assert.Check(t, is.DeepEqual(&NameID{
				Format:          want,
				NameQualifier:   nameidTestIDP,
				SPNameQualifier: nameidTestSP,
				Value:           "abc123",
			}, nameID))
		})
	}

	unqualified := []string{
		string(EmailAddressNameIDFormat),
		string(UnspecifiedNameIDFormat),
		entityNameIDFormat,
		"urn:oasis:names:tc:SAML:1.1:nameid-format:X509SubjectName",
		"urn:example:custom",
	}
	for _, format := range unqualified {
		t.Run("unqualified "+format, func(t *testing.T) {
			nameID, err := nameidMake(t, nameidRequest(t, test, nil), &Session{ID: "x", NameID: "alice@example.com", NameIDFormat: format})
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual(&NameID{Format: format, Value: "alice@example.com"}, nameID))
		})
	}
}

// TestNameIDPolicyIgnoredByDefault checks that, unless EnforceNameIDPolicy
// is set, the NameIDPolicy does not change the assertion, as before.
func TestNameIDPolicyIgnoredByDefault(t *testing.T) {
	test := idpcovNewTest(t)
	req := nameidRequest(t, test, nameidPolicy(string(PersistentNameIDFormat), "urn:affiliation:example"))
	nameID, err := nameidMake(t, req, &Session{ID: "x", NameID: "alice@example.com"})
	assert.NilError(t, err)
	assert.Check(t, is.DeepEqual(&NameID{
		Format:          string(TransientNameIDFormat),
		NameQualifier:   nameidTestIDP,
		SPNameQualifier: nameidTestSP,
		Value:           "alice@example.com",
	}, nameID))
}

// TestNameIDPolicyEnforcedFormat checks that with EnforceNameIDPolicy a
// requested Format other than unspecified or encrypted must be the one
// issued, or the request gets Requester / InvalidNameIDPolicy (saml-core
// §3.4.1.1).
func TestNameIDPolicyEnforcedFormat(t *testing.T) {
	test := idpcovNewTest(t)
	test.IDP.EnforceNameIDPolicy = true
	email := string(EmailAddressNameIDFormat)

	for name, tc := range map[string]struct {
		policy        *NameIDPolicy
		sessionFormat string
		wantErr       bool
	}{
		"no policy":                 {policy: nil, sessionFormat: email},
		"policy without format":     {policy: nameidPolicy("", ""), sessionFormat: email},
		"unspecified":               {policy: nameidPolicy(string(UnspecifiedNameIDFormat), ""), sessionFormat: email},
		"encrypted":                 {policy: nameidPolicy(encryptedNameIDFormat, ""), sessionFormat: email},
		"same format":               {policy: nameidPolicy(email, ""), sessionFormat: email},
		"transient default":         {policy: nameidPolicy(string(TransientNameIDFormat), ""), sessionFormat: ""},
		"other format":              {policy: nameidPolicy(string(PersistentNameIDFormat), ""), sessionFormat: email, wantErr: true},
		"email for default session": {policy: nameidPolicy(email, ""), sessionFormat: "", wantErr: true},
	} {
		t.Run(name, func(t *testing.T) {
			req := nameidRequest(t, test, tc.policy)
			nameID, err := nameidMake(t, req, &Session{ID: "x", NameID: "alice@example.com", NameIDFormat: tc.sessionFormat})
			if !tc.wantErr {
				assert.NilError(t, err)
				assert.Check(t, nameID != nil)
				return
			}
			var statusErr *StatusError
			assert.Assert(t, errors.As(err, &statusErr), "%v", err)
			assert.Check(t, is.Equal(StatusRequester, statusErr.TopLevel))
			assert.Check(t, is.Equal(StatusInvalidNameIDPolicy, statusErr.SecondLevel))
			assert.Check(t, req.Assertion == nil)
		})
	}
}

// TestNameIDPolicyEnforcedSPNameQualifier checks that with
// EnforceNameIDPolicy a requested SPNameQualifier is the one in the NameID
// (saml-core §3.4.1.1), except for the entity format, which must have none.
func TestNameIDPolicyEnforcedSPNameQualifier(t *testing.T) {
	test := idpcovNewTest(t)
	test.IDP.EnforceNameIDPolicy = true
	const affiliation = "urn:affiliation:example"

	for name, tc := range map[string]struct {
		sessionFormat string
		want          NameID
	}{
		"transient": {"", NameID{Format: string(TransientNameIDFormat), NameQualifier: nameidTestIDP, SPNameQualifier: affiliation}},
		"persistent": {string(PersistentNameIDFormat),
			NameID{Format: string(PersistentNameIDFormat), NameQualifier: nameidTestIDP, SPNameQualifier: affiliation}},
		"email":  {string(EmailAddressNameIDFormat), NameID{Format: string(EmailAddressNameIDFormat), SPNameQualifier: affiliation}},
		"entity": {entityNameIDFormat, NameID{Format: entityNameIDFormat}},
	} {
		t.Run(name, func(t *testing.T) {
			req := nameidRequest(t, test, nameidPolicy("", affiliation))
			nameID, err := nameidMake(t, req, &Session{ID: "x", NameID: "v", NameIDFormat: tc.sessionFormat})
			assert.NilError(t, err)
			tc.want.Value = "v"
			assert.Check(t, is.DeepEqual(&tc.want, nameID))
		})
	}
}

// TestNameIDPolicyEnforcedServeSSO checks that ServeSSO answers a request
// whose NameIDPolicy Format cannot be satisfied with an error Response.
func TestNameIDPolicyEnforcedServeSSO(t *testing.T) {
	test := idpErrNewTest(t)
	test.IDP.EnforceNameIDPolicy = true
	test.SP.AuthnNameIDFormat = PersistentNameIDFormat // the session is transient

	w := httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())

	el, _, _ := idpErrResponseFromForm(t, w.Body.Bytes())
	requestID := el.SelectAttrValue("InResponseTo", "")
	assert.Check(t, requestID != "")
	idpErrCheckErrorResponse(t, test, el, requestID, StatusRequester, StatusInvalidNameIDPolicy,
		"the name identifier format "+string(PersistentNameIDFormat)+" is not supported")

	// Without the option, the same request gets an assertion.
	test.IDP.EnforceNameIDPolicy = false
	w = httptest.NewRecorder()
	test.IDP.ServeSSO(w, idpcovSSORequest(t, test))
	assert.Assert(t, is.Equal(http.StatusOK, w.Code), w.Body.String())
	el, _, _ = idpErrResponseFromForm(t, w.Body.Bytes())
	assert.Check(t, is.Equal(StatusSuccess, el.FindElement("./Status/StatusCode").SelectAttrValue("Value", "")))
}
