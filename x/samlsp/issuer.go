package samlsp

import (
	"errors"
	"fmt"
	"time"

	"github.com/crewjam/saml"
)

// ErrUnexpectedIssuer is returned by ParseResponse, through a
// *saml.InvalidResponseError, when the Response is not from the identity
// provider of WithExpectedIssuer: the IdP that ParseResponse verifies it
// against, and so the Issuer of the Response and of its assertion, is
// another. The error also matches saml.ErrIssuerMismatch, so that code
// that already handles a wrong Issuer handles it too; ErrUnexpectedIssuer
// tells it apart as a Response from another IdP the SP trusts, rather
// than one whose Issuer does not match the IdP's metadata.
var ErrUnexpectedIssuer = errors.New("samlsp: the response is not from the identity provider the request was sent to")

// ErrConflictingIssuers is returned by ParseResponse when WithExpectedIssuer
// is passed more than once with different entity IDs: a Response can come
// from only one IdP. Parse a Response with the one login it may answer, as
// x/samlsp/pending finds it by the RelayState.
var ErrConflictingIssuers = errors.New("samlsp: WithExpectedIssuer names different identity providers")

// WithExpectedIssuer makes ParseResponse accept only a Response from the
// identity provider whose entity ID is entityID: the one the AuthnRequest
// was sent to (Message.IdentityProvider). Otherwise it fails with an error
// matching ErrUnexpectedIssuer and saml.ErrIssuerMismatch.
//
// ParseResponse verifies a Response against the IdP that it is given
// (WithIdentityProvider, IdentityProviderContext or the MetadataFunc of
// New), and package saml requires the Issuer of the Response and of its
// assertion to be that IdP. But the request ID alone does not say which
// IdP must answer: an SP that trusts several IdPs, one per tenant, and
// chooses the one to verify a Response with from the Response itself
// (PeekUnverifiedIssuer) would otherwise let one tenant's IdP answer a
// login started for another tenant's user, and log in whoever that IdP
// names. With this option, ParseResponse refuses metadata of any other
// IdP before it reads the request.
//
// x/samlsp/pending.Login.ResponseOption includes it. Use it directly when
// the application keeps its logins in progress elsewhere, such as in a
// server-side session that records Message.IdentityProvider.
//
// It can be passed more than once with the same entityID; with different
// ones ParseResponse returns ErrConflictingIssuers. An empty entityID is an
// error, so that a missing record does not turn the check off unnoticed.
func WithExpectedIssuer(entityID string) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) {
		o.expectedIssuers = append(o.expectedIssuers, entityID)
	})
}

// ResponseOptions returns a ResponseOption that applies opts in order, so
// that a package can offer several as one, as
// x/samlsp/pending.Login.ResponseOption does. Nil options are ignored.
func ResponseOptions(opts ...ResponseOption) ResponseOption {
	return responseOptionFunc(func(o *responseOptions) {
		for _, opt := range opts {
			if opt != nil {
				opt.applyResponse(o)
			}
		}
	})
}

// expectedIssuer returns the entity ID of WithExpectedIssuer, or "" if it
// was not passed.
func (o *responseOptions) expectedIssuer() (string, error) {
	var want string
	for i, id := range o.expectedIssuers {
		switch {
		case id == "":
			return "", errors.New("samlsp: WithExpectedIssuer needs an entity ID")
		case i == 0:
			want = id
		case id != want:
			return "", ErrConflictingIssuers
		}
	}
	return want, nil
}

// unexpectedIssuer returns the error of a Response from got rather than
// want, found at now.
func unexpectedIssuer(got, want string, now time.Time) error {
	return &saml.InvalidResponseError{
		PrivateErr: fmt.Errorf("%w: the response is from %q, not %q: %w", ErrUnexpectedIssuer, got, want, saml.ErrIssuerMismatch),
		Now:        now,
	}
}
