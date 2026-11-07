package saml

import "fmt"

// authnContextPasswordProtectedTransport is the authentication context class
// the IdP asserts when the Session does not say which one was achieved.
const authnContextPasswordProtectedTransport = "urn:oasis:names:tc:SAML:2.0:ac:classes:PasswordProtectedTransport" //nolint:gosec // G101: an authentication context class URI, not a credential

const authnContextClassPrefix = "urn:oasis:names:tc:SAML:2.0:ac:classes:"

// The Comparison values of a RequestedAuthnContext (saml-core §3.3.2.2.1).
const (
	authnContextComparisonExact   = "exact"
	authnContextComparisonMinimum = "minimum"
	authnContextComparisonMaximum = "maximum"
	authnContextComparisonBetter  = "better"
)

// DefaultAuthnContextClassStrengths returns the ranking of authentication
// context classes the IdP uses for the "minimum", "maximum" and "better"
// Comparisons of a RequestedAuthnContext when
// IdentityProvider.AuthnContextClassStrengths is nil. A higher number is
// stronger, and classes with the same number are equally strong:
//
//  1. InternetProtocol
//  2. InternetProtocolPassword, Password
//  3. PasswordProtectedTransport, SecureRemotePassword
//  4. Kerberos, PGP, SPKI, XMLDSig, TLSClient, X509, Smartcard, TimeSyncToken
//  5. SmartcardPKI
//
// All are classes of saml-authn-context-2.0-os. Any other class, such as
// unspecified or PreviousSession, is not ranked, and only satisfies a
// request for it by name. The ranking is a reasonable default, not part of
// the SAML specification, which leaves the ordering to the responder. The
// map returned is a new copy, which callers may extend and set as
// IdentityProvider.AuthnContextClassStrengths.
func DefaultAuthnContextClassStrengths() map[string]int {
	tiers := [][]string{
		{"InternetProtocol"},
		{"InternetProtocolPassword", "Password"},
		{"PasswordProtectedTransport", "SecureRemotePassword"},
		{"Kerberos", "PGP", "SPKI", "XMLDSig", "TLSClient", "X509", "Smartcard", "TimeSyncToken"},
		{"SmartcardPKI"},
	}
	strengths := map[string]int{}
	for i, tier := range tiers {
		for _, class := range tier {
			strengths[authnContextClassPrefix+class] = i + 1
		}
	}
	return strengths
}

// authnContextClassRef returns the AuthnContextClassRef to assert for
// session: session.AuthnContextClassRef, or PasswordProtectedTransport if
// that is empty. If the IdP has EnforceRequestedAuthnContext set and that
// class does not satisfy the request's RequestedAuthnContext, it returns a
// *StatusError instead: Responder with NoAuthnContext, or Requester for an
// unknown Comparison.
func (req *IdpAuthnRequest) authnContextClassRef(session *Session) (string, error) {
	achieved := authnContextPasswordProtectedTransport
	if session != nil && session.AuthnContextClassRef != "" {
		achieved = session.AuthnContextClassRef
	}
	if req.IDP == nil || !req.IDP.EnforceRequestedAuthnContext {
		return achieved, nil
	}
	if err := req.checkRequestedAuthnContext(achieved); err != nil {
		return "", err
	}
	return achieved, nil
}

// checkRequestedAuthnContext returns a *StatusError if the authentication
// context class achieved does not satisfy the request's
// RequestedAuthnContext. A request without one, or one that names no
// AuthnContextClassRef (only declarations, which are not evaluated), is
// always satisfied.
func (req *IdpAuthnRequest) checkRequestedAuthnContext(achieved string) error {
	requested := req.Request.RequestedAuthnContext
	if requested == nil || len(requested.ClassRefs()) == 0 {
		return nil
	}
	ok, known := authnContextSatisfies(requested.Comparison, requested.ClassRefs(), achieved, req.IDP.authnContextClassStrengths())
	if !known {
		return &StatusError{
			TopLevel: StatusRequester,
			Message:  fmt.Sprintf("unsupported RequestedAuthnContext Comparison %q", requested.Comparison),
		}
	}
	if !ok {
		return &StatusError{
			TopLevel:    StatusResponder,
			SecondLevel: StatusNoAuthnContext,
			Message:     "the requested authentication context cannot be satisfied",
		}
	}
	return nil
}

// authnContextClassStrengths returns AuthnContextClassStrengths, or
// DefaultAuthnContextClassStrengths if it is nil.
func (idp *IdentityProvider) authnContextClassStrengths() map[string]int {
	if idp.AuthnContextClassStrengths != nil {
		return idp.AuthnContextClassStrengths
	}
	return DefaultAuthnContextClassStrengths()
}

// authnContextSatisfies reports whether the class achieved satisfies the
// requested classes under comparison, following saml-core §3.3.2.2.1 as
// amended by errata E65, with strengths ranking the classes (a class not in
// it is not ranked). known is false for an unknown comparison.
//
//   - exact (or empty): achieved is one of the requested classes.
//   - minimum: achieved is one of them, or at least as strong as one of them.
//   - maximum: achieved is one of them, or no stronger than one of them.
//   - better: achieved is stronger than one of them.
//
// Only identical class references are considered the same class; a ranked
// comparison needs both classes to be ranked.
func authnContextSatisfies(comparison string, requested []string, achieved string, strengths map[string]int) (ok, known bool) {
	var match func(achieved, requested int) bool
	switch comparison {
	case "", authnContextComparisonExact:
		return containsString(requested, achieved), true
	case authnContextComparisonMinimum:
		match = func(a, r int) bool { return a >= r }
	case authnContextComparisonMaximum:
		match = func(a, r int) bool { return a <= r }
	case authnContextComparisonBetter:
		return authnContextRankedMatch(requested, achieved, strengths, func(a, r int) bool { return a > r }), true
	default:
		return false, false
	}
	return containsString(requested, achieved) || authnContextRankedMatch(requested, achieved, strengths, match), true
}

// authnContextRankedMatch reports whether achieved and at least one of the
// requested classes are ranked in strengths, and match holds for their
// strengths.
func authnContextRankedMatch(requested []string, achieved string, strengths map[string]int, match func(achieved, requested int) bool) bool {
	a, ok := strengths[achieved]
	if !ok {
		return false
	}
	for _, class := range requested {
		if r, ok := strengths[class]; ok && match(a, r) {
			return true
		}
	}
	return false
}

// containsString reports whether values contains value.
func containsString(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
