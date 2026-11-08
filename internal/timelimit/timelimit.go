// Package timelimit returns the clock skew and issue delay that a
// saml.ServiceProvider or saml.IdentityProvider allows: its own
// MaxClockSkew or MaxIssueDelay field or, if that is zero, the
// package-level saml.MaxClockSkew or saml.MaxIssueDelay.
package timelimit

import (
	"time"

	"github.com/crewjam/saml"
)

func or(d, fallback time.Duration) time.Duration {
	if d != 0 {
		return d
	}
	return fallback
}

// SPClockSkew returns the clock skew sp allows.
func SPClockSkew(sp *saml.ServiceProvider) time.Duration {
	return or(sp.MaxClockSkew, saml.MaxClockSkew)
}

// SPIssueDelay returns the issue delay sp allows.
func SPIssueDelay(sp *saml.ServiceProvider) time.Duration {
	return or(sp.MaxIssueDelay, saml.MaxIssueDelay)
}

// IDPClockSkew returns the clock skew idp allows.
func IDPClockSkew(idp *saml.IdentityProvider) time.Duration {
	return or(idp.MaxClockSkew, saml.MaxClockSkew)
}

// IDPIssueDelay returns the issue delay idp allows.
func IDPIssueDelay(idp *saml.IdentityProvider) time.Duration {
	return or(idp.MaxIssueDelay, saml.MaxIssueDelay)
}
