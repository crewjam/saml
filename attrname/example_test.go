package attrname_test

import (
	"fmt"

	"github.com/crewjam/saml/attrname"
)

func Example() {
	// Attributes as a service provider might receive them, keyed by Name.
	attributes := map[string]string{
		attrname.Mail:      "alice@example.com",
		attrname.GivenName: "Alice",
	}
	fmt.Println(attributes[attrname.Mail], attributes[attrname.GivenName])
	// Output: alice@example.com Alice
}
