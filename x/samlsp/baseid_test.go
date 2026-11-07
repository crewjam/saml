package samlsp_test

import (
	"errors"
	"testing"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// baseIDMaker makes the IdP identify the subject with a BaseID.
type baseIDMaker struct{}

func (baseIDMaker) MakeAssertion(req *saml.IdpAuthnRequest, session *saml.Session) error {
	if err := (saml.DefaultAssertionMaker{}).MakeAssertion(req, session); err != nil {
		return err
	}
	base := etree.NewElement("saml:BaseID")
	base.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	base.CreateAttr("xmlns:xsi", "http://www.w3.org/2001/XMLSchema-instance")
	base.CreateAttr("xmlns:ex", "urn:example:baseid")
	base.CreateAttr("xsi:type", "ex:EmployeeNumber")
	base.SetText("E-1234")
	req.Assertion.Subject.NameID = nil
	req.Assertion.Subject.BaseID = base
	return nil
}

func TestAcceptBaseID(t *testing.T) {
	ti := newTestIDP(t)
	ti.idp.AssertionMaker = baseIDMaker{}

	// Refused by default.
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID)); !errors.Is(err, saml.ErrUnsupported) {
		t.Fatalf("BaseID without AcceptBaseID: err = %v, want ErrUnsupported", err)
	}

	cfg = newTestConfig(t, ti, samlsp.AcceptBaseID)
	msg, err = cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
	}
	if a.BaseID == nil || a.BaseID.Text() != "E-1234" || a.BaseID.SelectAttrValue("xsi:type", "") != "ex:EmployeeNumber" {
		t.Errorf("BaseID = %v", a.BaseID)
	}
	if a.NameID.Value != "" || a.Subject != "" {
		t.Errorf("NameID %+v and Subject %q set with a BaseID", a.NameID, a.Subject)
	}
}
