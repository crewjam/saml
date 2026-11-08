package samlidp_test

import (
	"context"
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

// deliver posts msg to the SP's ACS and returns what ParseResponse makes
// of it.
func (p *pair) deliver(t *testing.T, msg *samlidp.Message, opts ...samlsp.ResponseOption) (*samlsp.Assertion, error) {
	t.Helper()
	return p.sp.ParseResponse(context.Background(), postForm(t, msg.Destination, formOf(t, msg)), opts...)
}

// wantSPStatus checks that err is the error of a Response with this
// top-level status, as the SP sees it.
func wantSPStatus(t *testing.T, err error, topLevel string) {
	t.Helper()
	var bad saml.ErrBadStatus
	if !errors.As(err, &bad) {
		t.Fatalf("got %v, want a bad status", err)
	}
	if bad.Status != topLevel {
		t.Fatalf("status = %q, want %q", bad.Status, topLevel)
	}
}

func asStatus(t *testing.T, err error, topLevel, secondLevel string) *saml.StatusError {
	t.Helper()
	var status *saml.StatusError
	if !errors.As(err, &status) {
		t.Fatalf("got %v, want a *saml.StatusError", err)
	}
	if status.TopLevel != topLevel || status.SecondLevel != secondLevel {
		t.Fatalf("status = %q / %q, want %q / %q", status.TopLevel, status.SecondLevel, topLevel, secondLevel)
	}
	return status
}

// parse sends a fresh AuthnRequest of the SP to the IdP.
func (p *pair) parse(t *testing.T, opts ...samlsp.AuthnOption) (*samlsp.Message, *samlidp.AuthnRequest, error) {
	t.Helper()
	msg, err := p.sp.AuthnRequest(context.Background(), "rs", opts...)
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.idp.ParseAuthnRequest(context.Background(), browserRequest(t, msg))
	return msg, req, err
}

func TestIsPassive(t *testing.T) {
	p := newPair(t, nil, nil)
	msg, req, err := p.parse(t, samlsp.IsPassive)
	if err != nil {
		t.Fatal(err)
	}
	if !req.IsPassive || req.ForceAuthn {
		t.Fatalf("got %+v", req)
	}
	resp, err := p.idp.ErrorResponse(context.Background(), req, &saml.StatusError{
		TopLevel: saml.StatusResponder, SecondLevel: saml.StatusNoPassive, Message: "no session",
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.InResponseTo != msg.ID {
		t.Errorf("InResponseTo = %q", resp.InResponseTo)
	}
	_, err = p.deliver(t, resp, samlsp.WithRequestID(msg.ID))
	wantSPStatus(t, err, saml.StatusResponder)
}

func TestForceAuthn(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.ForceAuthn)
	if err != nil {
		t.Fatal(err)
	}
	if !req.ForceAuthn {
		t.Fatalf("got %+v", req)
	}
}

func TestNameIDPolicy(t *testing.T) {
	p := newPair(t, nil, nil)
	msg, req, err := p.parse(t) // x/samlsp asks for transient
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject
	subject.NameIDFormat = saml.PersistentNameIDFormat
	_, err = p.idp.Response(context.Background(), req, subject)
	status := asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)
	resp, err := p.idp.ErrorResponse(context.Background(), req, status)
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.deliver(t, resp, samlsp.WithRequestID(msg.ID))
	wantSPStatus(t, err, saml.StatusRequester)

	// An SP that asks for the persistent format gets it, qualified.
	p = newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(saml.PersistentNameIDFormat)})
	a, _ := p.login(t, nil, subject)
	if a.NameID.Format != string(saml.PersistentNameIDFormat) || a.NameID.NameQualifier != idpEntityID || a.NameID.SPNameQualifier != spEntityID {
		t.Fatalf("NameID = %+v", a.NameID)
	}

	// Relaxed, the IdP issues what it likes.
	p = newPair(t, []samlidp.Option{samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.EnforceNameIDPolicy = false })}, nil)
	_, req, err = p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.Response(context.Background(), req, subject); err != nil {
		t.Fatal(err)
	}
}

func TestAuthnContext(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509))
	if err != nil {
		t.Fatal(err)
	}
	_, err = p.idp.Response(context.Background(), req, testSubject) // PasswordProtectedTransport
	_ = asStatus(t, err, saml.StatusResponder, saml.StatusNoAuthnContext)
}

// A RequestedAuthnContext of declarations only cannot be satisfied by the
// classes the IdP asserts (saml-core §3.3.2.2.1).
func TestAuthnContextDeclRef(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.WithModify(func(r *saml.AuthnRequest) error {
		r.RequestedAuthnContext = &saml.RequestedAuthnContext{
			Comparison:           string(saml.AuthnContextComparisonExact),
			AuthnContextDeclRefs: []string{"urn:example:decl:mfa"},
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if len(req.AuthnContextDecls) != 1 || req.AuthnContextDecls[0] != "urn:example:decl:mfa" || len(req.AuthnContextClasses) != 0 {
		t.Fatalf("AuthnContextDecls %v, AuthnContextClasses %v", req.AuthnContextDecls, req.AuthnContextClasses)
	}
	_, err = p.idp.Response(context.Background(), req, testSubject)
	_ = asStatus(t, err, saml.StatusResponder, saml.StatusNoAuthnContext)
}

func TestRequestedSubject(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.WithSubject(saml.NameID{Value: "someone-else"}))
	if err != nil {
		t.Fatal(err)
	}
	if req.Subject == nil || req.Subject.Value != "someone-else" {
		t.Fatalf("Subject = %+v", req.Subject)
	}
	_, err = p.idp.Response(context.Background(), req, testSubject)
	_ = asStatus(t, err, saml.StatusRequester, saml.StatusUnknownPrincipal)

	subject := testSubject
	subject.NameID = "someone-else"
	if _, err := p.idp.Response(context.Background(), req, subject); err != nil {
		t.Fatal(err)
	}
}

func TestUnknownServiceProvider(t *testing.T) {
	p := newPair(t, nil, nil)
	other, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.sp.AuthnRequest(context.Background(), "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := other.ParseAuthnRequest(context.Background(), browserRequest(t, msg))
	if !errors.Is(err, samlidp.ErrUnknownServiceProvider) || req != nil {
		t.Fatalf("got %v, %v", req, err)
	}
	if _, err := other.IDPInitiated(context.Background(), spEntityID, ""); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Fatalf("IDPInitiated: got %v", err)
	}
}

func TestExpiredRequest(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) { testExpiredRequest(t, binding) })
	}
}

func testExpiredRequest(t *testing.T, binding string) {
	p := newPair(t, nil, nil)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "rs", samlsp.WithBinding(binding))
	if err != nil {
		t.Fatal(err)
	}
	later, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(p.sp.Metadata(ctx)),
		samlidp.WithSigningKey(idpKey, idpCert), samlidp.WithClock(dsig.NewFakeClockAt(time.Now().Add(time.Hour))))
	if err != nil {
		t.Fatal(err)
	}
	req, err := later.ParseAuthnRequest(ctx, browserRequest(t, msg))
	if !errors.Is(err, saml.ErrExpired) {
		t.Fatalf("got %v, want it to match saml.ErrExpired", err)
	}
	status := asStatus(t, err, saml.StatusRequester, "")
	if req == nil || req.ID != msg.ID || req.ACSURL != p.sp.ACSURL() {
		t.Fatalf("got %+v", req)
	}
	resp, err := later.ErrorResponse(ctx, req, status)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Destination != p.sp.ACSURL() || resp.InResponseTo != msg.ID {
		t.Fatalf("got %+v", resp)
	}
}

func TestUnsupportedACSBinding(t *testing.T) {
	// The SP asks for its HTTP-Artifact ACS, which this IdP cannot send to.
	const artifactACS = "https://sp.example.com/saml/artifact"
	p := newPair(t, nil, nil)
	ctx := context.Background()
	md := p.sp.Metadata(ctx)
	d := &md.SPSSODescriptors[0]
	d.AssertionConsumerServices = append([]saml.IndexedEndpoint{{
		Binding: saml.HTTPArtifactBinding, Location: artifactACS, Index: 9,
	}}, d.AssertionConsumerServices...)
	idp, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(md), samlidp.WithSigningKey(idpKey, idpCert))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.sp.AuthnRequest(ctx, "", samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		req.AssertionConsumerServiceURL = artifactACS
		req.ProtocolBinding = saml.HTTPArtifactBinding
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	req, err := idp.ParseAuthnRequest(ctx, browserRequest(t, msg))
	status := asStatus(t, err, saml.StatusRequester, saml.StatusUnsupportedBinding)
	if req == nil || req.ACSURL != p.sp.ACSURL() || req.ACSBinding != saml.HTTPPostBinding {
		t.Fatalf("the error goes to %+v, not the default ACS", req)
	}
	resp, err := idp.ErrorResponse(ctx, req, status)
	if err != nil {
		t.Fatal(err)
	}
	if resp.Destination != p.sp.ACSURL() {
		t.Fatalf("Destination = %q", resp.Destination)
	}
}

func TestTamperedACS(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	req.ACSURL = "https://evil.example.com/acs"
	if _, err := p.idp.Response(context.Background(), req, testSubject); !errors.Is(err, saml.ErrUnknownAssertionConsumerService) {
		t.Fatalf("got %v", err)
	}
	req.ServiceProvider = "https://evil.example.com"
	if _, err := p.idp.Response(context.Background(), req, testSubject); !errors.Is(err, samlidp.ErrUnknownServiceProvider) {
		t.Fatalf("got %v", err)
	}
}

func TestSubjectRequired(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.Response(context.Background(), req, samlidp.Subject{AuthnInstant: time.Now()}); err == nil {
		t.Error("no NameID: no error")
	}
	if _, err := p.idp.Response(context.Background(), req, samlidp.Subject{NameID: "x"}); err == nil {
		t.Error("no AuthnInstant: no error")
	}
	if _, err := p.idp.ErrorResponse(context.Background(), req, nil); err == nil {
		t.Error("no status: no error")
	}
}

func TestIDPInitiated(t *testing.T) {
	p := newPair(t, nil, nil)
	ctx := context.Background()
	req, err := p.idp.IDPInitiated(ctx, spEntityID, "/dashboard")
	if err != nil {
		t.Fatal(err)
	}
	if req.ID != "" || req.ACSURL != p.sp.ACSURL() || req.RelayState != "/dashboard" {
		t.Fatalf("got %+v", req)
	}
	resp, err := p.idp.Response(ctx, req, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.deliver(t, resp); !errors.Is(err, samlsp.ErrNoRequestID) {
		t.Fatalf("solicited only: got %v", err)
	}
	a, err := p.deliver(t, resp, samlsp.AllowUnsolicited)
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != testSubject.NameID || a.InResponseTo != "" {
		t.Fatalf("got %+v", a)
	}

	long := string(make([]byte, 81))
	if _, err := p.idp.IDPInitiated(ctx, spEntityID, long); !errors.Is(err, saml.ErrRelayStateTooLong) {
		t.Fatalf("long RelayState: got %v", err)
	}
}

func TestWithAssertion(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	boom := errors.New("boom")
	_, err = p.idp.Response(context.Background(), req, testSubject, samlidp.WithAssertion(func(*saml.Assertion) error { return boom }))
	if !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}
}

// ParseAuthnRequest leaves the caller's request with its form parsed, so
// that the application can read its own fields of the same POST.
func TestParseAuthnRequestKeepsForm(t *testing.T) {
	p := newPair(t, nil, nil)
	msg, err := p.sp.AuthnRequest(context.Background(), "rs", samlsp.WithBinding(saml.HTTPPostBinding))
	if err != nil {
		t.Fatal(err)
	}
	fields := formOf(t, msg)
	fields.Set("remember", "yes")
	r := postForm(t, msg.Destination, fields)
	if _, err := p.idp.ParseAuthnRequest(context.Background(), r); err != nil {
		t.Fatal(err)
	}
	if got := r.FormValue("remember"); got != "yes" {
		t.Fatalf("remember = %q", got)
	}
}

// AllowCreate is false only when the SP's NameIDPolicy forbids creating an
// identifier: a request without a NameIDPolicy leaves the identifier to
// the IdP (saml-core §3.4.1), and transient identifiers are always new.
func TestAllowCreate(t *testing.T) {
	no, yes := false, true
	persistent, transient := string(saml.PersistentNameIDFormat), string(saml.TransientNameIDFormat)
	for _, tc := range []struct {
		name   string
		policy *saml.NameIDPolicy
		want   bool
	}{
		{"no NameIDPolicy", nil, true},
		{"AllowCreate true", &saml.NameIDPolicy{Format: &persistent, AllowCreate: &yes}, true},
		{"AllowCreate false", &saml.NameIDPolicy{Format: &persistent, AllowCreate: &no}, false},
		{"AllowCreate omitted", &saml.NameIDPolicy{Format: &persistent}, false},
		{"transient, AllowCreate false", &saml.NameIDPolicy{Format: &transient, AllowCreate: &no}, true},
	} {
		p := newPair(t, nil, nil)
		_, req, err := p.parse(t, samlsp.WithModify(func(r *saml.AuthnRequest) error {
			r.NameIDPolicy = tc.policy
			return nil
		}))
		if err != nil {
			t.Fatalf("%s: %v", tc.name, err)
		}
		if req.AllowCreate != tc.want {
			t.Errorf("%s: AllowCreate = %v", tc.name, req.AllowCreate)
		}
	}
}
