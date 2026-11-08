package samlsp_test

import (
	"errors"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// WithClockSkew and WithMaxIssueDelay set the fields of each
// saml.ServiceProvider the Config builds, and ClockSkew and MaxIssueDelay
// report them, or the package defaults.
func TestTimeLimitOptions(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	if got := cfg.ClockSkew(); got != saml.MaxClockSkew {
		t.Errorf("default ClockSkew = %s, want %s", got, saml.MaxClockSkew)
	}
	if got := cfg.MaxIssueDelay(); got != saml.MaxIssueDelay {
		t.Errorf("default MaxIssueDelay = %s, want %s", got, saml.MaxIssueDelay)
	}

	cfg = newTestConfig(t, ti, samlsp.WithClockSkew(7*time.Minute), samlsp.WithMaxIssueDelay(5*time.Minute))
	if got := cfg.ClockSkew(); got != 7*time.Minute {
		t.Errorf("ClockSkew = %s", got)
	}
	if got := cfg.MaxIssueDelay(); got != 5*time.Minute {
		t.Errorf("MaxIssueDelay = %s", got)
	}
	sp, err := cfg.ServiceProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if sp.MaxClockSkew != 7*time.Minute || sp.MaxIssueDelay != 5*time.Minute {
		t.Errorf("ServiceProvider MaxClockSkew %s, MaxIssueDelay %s", sp.MaxClockSkew, sp.MaxIssueDelay)
	}

	if _, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithClockSkew(-time.Second)); err == nil {
		t.Error("New accepted a negative clock skew")
	}
}

// WithMaxAuthnAge allows the configured clock skew, not saml.MaxClockSkew.
func TestWithMaxAuthnAgeUsesClockSkew(t *testing.T) {
	const maxAge = 10 * time.Minute
	age := maxAge + saml.MaxClockSkew - time.Minute
	for _, tc := range []struct {
		skew    time.Duration
		wantErr bool
	}{
		{0, false},
		{time.Second, true},
	} {
		ti := newTestIDP(t)
		ti.authnAge = age
		cfg := newTestConfig(t, ti, samlsp.WithClockSkew(tc.skew))
		msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.ForceAuthn)
		if err != nil {
			t.Fatal(err)
		}
		_, err = cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID), samlsp.WithMaxAuthnAge(maxAge))
		if got := errors.Is(err, samlsp.ErrAuthnTooOld); got != tc.wantErr {
			t.Errorf("skew %s: err = %v, want ErrAuthnTooOld %t", tc.skew, err, tc.wantErr)
		}
	}
}
