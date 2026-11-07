package samlidp

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml"
)

// Tests for the NameID formats samlidp advertises and issues (issue #868).

// TestMetadataAdvertisesIssuedNameIDFormats checks that the samlidp metadata
// lists the formats samlidp issues: emailAddress for users with an email
// address and transient for the others (saml-metadata §2.4.3).
func TestMetadataAdvertisesIssuedNameIDFormats(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	idpSSO := s.IDP.Metadata().IDPSSODescriptors
	assert.Assert(t, is.Len(idpSSO, 1))
	assert.Check(t, is.DeepEqual([]saml.NameIDFormat{
		saml.EmailAddressNameIDFormat,
		saml.TransientNameIDFormat,
	}, idpSSO[0].NameIDFormats))
}

// TestMetadataNameIDFormatsCanBeOverridden checks that NameIDFormats set on
// the IdentityProvider after New are the ones advertised.
func TestMetadataNameIDFormatsCanBeOverridden(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.IDP.NameIDFormats = []saml.NameIDFormat{saml.PersistentNameIDFormat}
	idpSSO := s.IDP.Metadata().IDPSSODescriptors
	assert.Assert(t, is.Len(idpSSO, 1))
	assert.Check(t, is.DeepEqual([]saml.NameIDFormat{saml.PersistentNameIDFormat}, idpSSO[0].NameIDFormats))
}

// nameIDFormatsSession logs in the user alice, created with the given JSON,
// and returns her session.
func nameIDFormatsSession(t *testing.T, s *Server, userJSON string) *saml.Session {
	t.Helper()
	w := covServe(s, "PUT", "/users/alice", userJSON)
	assert.Assert(t, is.Equal(http.StatusNoContent, w.Code))
	r := covLoginRequest("user=alice&password=hunter2")
	assert.NilError(t, r.ParseForm())
	session := s.GetSession(httptest.NewRecorder(), r, &saml.IdpAuthnRequest{IDP: &s.IDP})
	assert.Assert(t, session != nil)
	return session
}

// nameIDFormatsAssert runs DefaultAssertionMaker for session with an
// AuthnRequest whose NameIDPolicy asks for format, and returns the NameID
// issued or the error.
func nameIDFormatsAssert(t *testing.T, s *Server, session *saml.Session, format saml.NameIDFormat) (*saml.NameID, error) {
	t.Helper()
	f := string(format)
	r := httptest.NewRequest("POST", "https://idp.example.com/sso", nil)
	req := &saml.IdpAuthnRequest{
		IDP:         &s.IDP,
		HTTPRequest: r,
		Now:         saml.TimeNow(),
		Request: saml.AuthnRequest{
			ID:           "id-868",
			IssueInstant: saml.TimeNow(),
			NameIDPolicy: &saml.NameIDPolicy{Format: &f},
		},
		ServiceProviderMetadata: &saml.EntityDescriptor{EntityID: "https://sp.example.com/saml2/metadata"},
		SPSSODescriptor:         &saml.SPSSODescriptor{},
		ACSEndpoint:             &saml.IndexedEndpoint{Binding: saml.HTTPPostBinding, Location: "https://sp.example.com/saml2/acs"},
	}
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return nil, err
	}
	assert.Assert(t, req.Assertion != nil && req.Assertion.Subject != nil)
	return req.Assertion.Subject.NameID, nil
}

func assertInvalidNameIDPolicy(t *testing.T, err error) {
	t.Helper()
	var statusErr *saml.StatusError
	assert.Assert(t, errors.As(err, &statusErr), "got %v", err)
	assert.Check(t, is.Equal(saml.StatusRequester, statusErr.TopLevel))
	assert.Check(t, is.Equal(saml.StatusInvalidNameIDPolicy, statusErr.SecondLevel))
}

// TestEnforceNameIDPolicyWithEmail checks that, with EnforceNameIDPolicy, a
// samlidp IdP gives a user with an email address an emailAddress NameID
// when the service provider asks for it, or for the first format the IdP
// advertises, and refuses a request for transient, which it does not issue
// to that user.
func TestEnforceNameIDPolicyWithEmail(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.IDP.EnforceNameIDPolicy = true
	session := nameIDFormatsSession(t, s, `{"password": "hunter2", "email": "alice@example.com"}`)

	first := s.IDP.Metadata().IDPSSODescriptors[0].NameIDFormats[0]
	for _, format := range []saml.NameIDFormat{saml.EmailAddressNameIDFormat, first, saml.UnspecifiedNameIDFormat} {
		nameID, err := nameIDFormatsAssert(t, s, session, format)
		assert.NilError(t, err, "format %s", format)
		assert.Check(t, is.Equal(string(saml.EmailAddressNameIDFormat), nameID.Format))
		assert.Check(t, is.Equal("alice@example.com", nameID.Value))
	}

	_, err := nameIDFormatsAssert(t, s, session, saml.TransientNameIDFormat)
	assertInvalidNameIDPolicy(t, err)
}

// TestEnforceNameIDPolicyWithoutEmail checks that, with
// EnforceNameIDPolicy, a user without an email address gets a transient
// NameID when the service provider asks for transient or unspecified, and
// that a request for emailAddress is refused for that user.
func TestEnforceNameIDPolicyWithoutEmail(t *testing.T) {
	s := covNewServer(t, &MemoryStore{})
	s.IDP.EnforceNameIDPolicy = true
	session := nameIDFormatsSession(t, s, `{"password": "hunter2"}`)

	for _, format := range []saml.NameIDFormat{saml.TransientNameIDFormat, saml.UnspecifiedNameIDFormat} {
		nameID, err := nameIDFormatsAssert(t, s, session, format)
		assert.NilError(t, err, "format %s", format)
		assert.Check(t, is.Equal(string(saml.TransientNameIDFormat), nameID.Format))
	}

	_, err := nameIDFormatsAssert(t, s, session, saml.EmailAddressNameIDFormat)
	assertInvalidNameIDPolicy(t, err)
}

// TestServiceProviderRequestsAdvertisedNameIDFormat checks the documented
// way for a service provider to work with a samlidp IdP that enforces the
// NameIDPolicy: setting AuthnNameIDFormat to the first format the IdP
// advertises puts that format in the AuthnRequest.
func TestServiceProviderRequestsAdvertisedNameIDFormat(t *testing.T) {
	test := NewServerTest(t)
	test.SP.AuthnNameIDFormat = test.SP.IDPMetadata.IDPSSODescriptors[0].NameIDFormats[0]
	req, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(saml.HTTPRedirectBinding),
		saml.HTTPRedirectBinding, saml.HTTPPostBinding)
	assert.NilError(t, err)
	assert.Assert(t, req.NameIDPolicy != nil && req.NameIDPolicy.Format != nil)
	assert.Check(t, is.Equal(string(saml.EmailAddressNameIDFormat), *req.NameIDPolicy.Format))
}
