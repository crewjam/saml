package samlsp

import (
	"github.com/crewjam/saml"
)

var _ SamlAssertionHandler = BasicSamlAssertionHandler{}

type BasicSamlAssertionHandler struct{}

func (as BasicSamlAssertionHandler) HandleAssertion(assertion *saml.Assertion) error {
	return nil
}
