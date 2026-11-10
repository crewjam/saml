package samlsp_test

import (
	"errors"
	"slices"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// emailClaim is the AD FS claim type of the user's email address.
const emailClaim = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/emailaddress"

// noNameIDMaker makes the IdP answer as AD FS does when its relying party
// trust has no claim rule issuing a Name ID (issue #989): the Subject has
// only a bearer SubjectConfirmation, and the user is named by the
// emailaddress claim.
type noNameIDMaker struct{}

func (noNameIDMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}
	req.Assertion.Subject.NameID = nil
	req.Assertion.AttributeStatements = []saml.AttributeStatement{{
		Attributes: []saml.Attribute{{
			Name:   emailClaim,
			Values: []saml.AttributeValue{{Type: "xs:string", Value: "foo@bar.com"}},
		}},
	}}
	return nil
}

// The identifier of a Subject is optional (saml-core §2.4.1), so
// ParseResponse accepts an assertion without one, with NameID and Subject
// empty, and the caller names the user by an attribute.
func TestParseResponseWithoutSubjectIdentifier(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.AssertionMaker = noNameIDMaker{}
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
	}
	if a.NameID != (saml.NameID{}) || a.Subject != "" || a.BaseID != nil {
		t.Errorf("NameID %+v, Subject %q, BaseID %v; want all empty", a.NameID, a.Subject, a.BaseID)
	}
	if a.InResponseTo != msg.ID {
		t.Errorf("InResponseTo = %q, want %q", a.InResponseTo, msg.ID)
	}
	if got := a.Attributes.Values(emailClaim); !slices.Equal(got, []string{"foo@bar.com"}) {
		t.Errorf("email = %q, want [foo@bar.com]", got)
	}
}
