package server

import (
	"testing"
	"time"

	"github.com/crewjam/saml"
)

func TestValidity(t *testing.T) {
	nb := time.Date(2026, 1, 2, 15, 31, 15, 0, time.UTC)
	a := &saml.Assertion{
		Conditions:      &saml.Conditions{NotBefore: nb, NotOnOrAfter: nb.Add(80 * time.Second)},
		AuthnStatements: []saml.AuthnStatement{{AuthnInstant: nb.Add(10 * time.Second)}},
	}
	v := validity(a, nb.Add(20*time.Second), true)
	if v.Len != "80 seconds" || v.Mid != "authenticated" || v.Mark != "at-15" || v.Late {
		t.Errorf("accepted: %+v", v)
	}
	v = validity(a, nb.Add(80*time.Second+3*time.Minute), false)
	if v.Len != "80 seconds, expired" || v.Mid != "arrived 3 minutes after expiry" || !v.Late {
		t.Errorf("late: %+v", v)
	}
	if validity(&saml.Assertion{}, nb, true) != nil {
		t.Error("a window without Conditions")
	}
}

func TestRelaxedBy(t *testing.T) {
	cfg := &SPConfig{AllowSHA1: true}
	signed := `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="r1"><saml:Assertion ID="a1"><ds:Signature xmlns:ds="http://www.w3.org/2000/09/xmldsig#"><ds:SignedInfo><ds:CanonicalizationMethod Algorithm="http://www.w3.org/2001/10/xml-exc-c14n#"/><ds:SignatureMethod Algorithm="http://www.w3.org/2000/09/xmldsig#rsa-sha1"/><ds:Reference URI="#a1"><ds:DigestMethod Algorithm="http://www.w3.org/2000/09/xmldsig#sha1"/><ds:DigestValue>x</ds:DigestValue></ds:Reference></ds:SignedInfo><ds:SignatureValue>x</ds:SignatureValue></ds:Signature></saml:Assertion></samlp:Response>`
	reasons, sig := relaxedBy(cfg, signed, "", time.Now())
	if len(reasons) != 1 || reasons[0] != "the assertion is signed with rsa-sha1" || sig != "rsa-sha1 · accepted by Relax checks" {
		t.Errorf("got %q, %q", reasons, sig)
	}
	if reasons, _ := relaxedBy(&SPConfig{}, signed, "", time.Now()); reasons != nil {
		t.Errorf("default checks: %q", reasons)
	}
}
