package samlsp

import (
	"github.com/crewjam/saml"
)

var _ SamlAssertionHandler = BasicSamlAssertionHandler{}

// BasicSamlAssertionHandler is an implementation of SamlAssertionHandler that has
// an empty HandleAssertion function to retain useability.
type BasicSamlAssertionHandler struct{}

// HandleAssertion is called and passed saml assertion
// this can add extra functionality and should return any error that occurs.
func (as BasicSamlAssertionHandler) HandleAssertion(assertion *saml.Assertion) error {
	return nil
}
