package samlidp_test

import (
	"context"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

// WithClockSkew and WithMaxIssueDelay set the fields of each
// saml.IdentityProvider the Config builds, and ClockSkew and MaxIssueDelay
// report them, or the package defaults.
func TestTimeLimitOptions(t *testing.T) {
	p := newPair(t, nil, nil)
	if got := p.idp.ClockSkew(); got != saml.MaxClockSkew {
		t.Errorf("default ClockSkew = %s, want %s", got, saml.MaxClockSkew)
	}
	if got := p.idp.MaxIssueDelay(); got != saml.MaxIssueDelay {
		t.Errorf("default MaxIssueDelay = %s, want %s", got, saml.MaxIssueDelay)
	}

	p = newPair(t, []samlidp.Option{samlidp.WithClockSkew(7 * time.Minute), samlidp.WithMaxIssueDelay(5 * time.Minute)}, nil)
	if got := p.idp.ClockSkew(); got != 7*time.Minute {
		t.Errorf("ClockSkew = %s", got)
	}
	if got := p.idp.MaxIssueDelay(); got != 5*time.Minute {
		t.Errorf("MaxIssueDelay = %s", got)
	}
	idp := p.idp.IdentityProvider()
	if idp.MaxClockSkew != 7*time.Minute || idp.MaxIssueDelay != 5*time.Minute {
		t.Errorf("IdentityProvider MaxClockSkew %s, MaxIssueDelay %s", idp.MaxClockSkew, idp.MaxIssueDelay)
	}

	if _, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert), samlidp.WithMaxIssueDelay(-time.Second)); err == nil {
		t.Error("New accepted a negative issue delay")
	}
}

// The ForceAuthn check of Response allows the configured clock skew.
func TestForceAuthnInstantUsesClockSkew(t *testing.T) {
	p := newPair(t, []samlidp.Option{samlidp.WithClockSkew(time.Second)}, nil)
	_, req, err := p.parse(t, samlsp.ForceAuthn)
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject
	subject.AuthnInstant = req.IssueInstant.Add(-time.Minute)
	if _, err := p.idp.Response(context.Background(), req, subject); err == nil {
		t.Error("Response accepted an AuthnInstant beyond the configured clock skew")
	}
}

// A negative clock skew or issue delay set by an IdentityProviderOption is
// refused too: by New, if the option is passed to it, and by the method
// it is passed to otherwise.
func TestNegativeTimeLimitIdentityProviderOption(t *testing.T) {
	keys(t)
	negative := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.MaxClockSkew = -time.Minute })
	if _, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert), negative); err == nil {
		t.Error("New accepted a negative clock skew")
	}

	p := newPair(t, nil, nil)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "rs")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg), negative); err == nil {
		t.Error("ParseAuthnRequest accepted a negative clock skew")
	}
	if _, err := p.idp.IDPInitiated(ctx, spEntityID, "", negative); err == nil {
		t.Error("IDPInitiated accepted a negative clock skew")
	}
	req, err := p.idp.IDPInitiated(ctx, spEntityID, "")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.Response(ctx, req, testSubject, negative); err == nil {
		t.Error("Response accepted a negative clock skew")
	}
	if _, err := p.idp.ErrorResponse(ctx, req, &saml.StatusError{TopLevel: saml.StatusResponder}, negative); err == nil {
		t.Error("ErrorResponse accepted a negative clock skew")
	}
	if _, err := p.idp.Response(ctx, req, testSubject); err != nil {
		t.Fatal(err)
	}
}
