package samlsp

import "github.com/crewjam/saml"

// SamlAssertionHandler is an interface implemented by types that can handle
// assertions and add extra functionality
type SamlAssertionHandler interface {
	HandleAssertion(assertion *saml.Assertion) error
}
