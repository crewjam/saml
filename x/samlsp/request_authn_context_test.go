package samlsp_test

import (
	"errors"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// WithRequest enforces the authentication context that the AuthnRequest
// asked for, without the AuthnContextOption being passed to
// ParseResponse again.
func TestWithRequestEnforcesAuthnContext(t *testing.T) {
	ti := newTestIDP(t) // authenticates with PasswordProtectedTransport
	cfg := newTestConfig(t, ti)

	for _, tt := range []struct {
		name    string
		ctx     samlsp.AuthnOption
		wantErr error
	}{
		{"none", nil, nil},
		{"satisfied", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509, saml.AuthnContextPasswordProtectedTransport), nil},
		{"not satisfied", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509), saml.ErrAuthnContextMismatch},
	} {
		msg, err := cfg.AuthnRequest(t.Context(), "s", tt.ctx)
		if err != nil {
			t.Fatal(err)
		}
		if (msg.RequestedAuthnContext() == nil) != (tt.ctx == nil) {
			t.Errorf("%s: RequestedAuthnContext = %+v", tt.name, msg.RequestedAuthnContext())
		}
		_, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequest(msg.ID, msg.RequestedAuthnContext()))
		if tt.wantErr == nil && err != nil || tt.wantErr != nil && !errors.Is(err, tt.wantErr) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.wantErr)
		}
	}

	// An AuthnContextOption passed to ParseResponse takes precedence.
	requireX509 := samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509)
	msg, err := cfg.AuthnRequest(t.Context(), "s", requireX509)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequest(msg.ID, msg.RequestedAuthnContext()),
		samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextPasswordProtectedTransport)); err != nil {
		t.Errorf("with an AuthnContextOption: %v", err)
	}
}

// RequestedAuthnContext returns a copy, which the caller may change.
func TestRequestedAuthnContextCopied(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithAuthnContext(saml.AuthnContextComparisonExact, saml.AuthnContextX509))
	if err != nil {
		t.Fatal(err)
	}
	rac := msg.RequestedAuthnContext()
	rac.AuthnContextClassRefs[0] = string(saml.AuthnContextPasswordProtectedTransport)
	if got := msg.RequestedAuthnContext().AuthnContextClassRefs[0]; got != string(saml.AuthnContextX509) {
		t.Errorf("changing the copy changed the message: %s", got)
	}
}

// Requests that asked for different authentication contexts cannot be
// enforced by one check: ParseResponse refuses them all, rather than
// enforcing one request's context, or none, on a Response to another.
func TestWithRequestConflicting(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	x509 := &saml.RequestedAuthnContext{Comparison: "exact", AuthnContextClassRefs: []string{string(saml.AuthnContextX509)}}
	ppt := &saml.RequestedAuthnContext{AuthnContextClassRefs: []string{string(saml.AuthnContextPasswordProtectedTransport)}}
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	for _, tt := range []struct {
		name string
		opts []samlsp.ResponseOption
		want error
	}{
		{"different classes", []samlsp.ResponseOption{samlsp.WithRequest("a", x509), samlsp.WithRequest(msg.ID, ppt)}, samlsp.ErrConflictingAuthnContexts},
		{"one asked for none", []samlsp.ResponseOption{samlsp.WithRequest("a", x509), samlsp.WithRequestID(msg.ID)}, samlsp.ErrConflictingAuthnContexts},
		// The same request given twice, once without its context, is one.
		{"same request", []samlsp.ResponseOption{samlsp.WithRequestID(msg.ID), samlsp.WithRequest(msg.ID, x509)}, saml.ErrAuthnContextMismatch},
		// An empty Comparison is exact.
		{"same context", []samlsp.ResponseOption{samlsp.WithRequest("a", ppt), samlsp.WithRequest(msg.ID, &saml.RequestedAuthnContext{Comparison: "exact", AuthnContextClassRefs: ppt.AuthnContextClassRefs})}, nil},
	} {
		_, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), tt.opts...)
		if tt.want == nil && err != nil || tt.want != nil && !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", tt.name, err, tt.want)
		}
	}
}
