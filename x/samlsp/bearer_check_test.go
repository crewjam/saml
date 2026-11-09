package samlsp

import (
	"testing"
	"time"

	"github.com/crewjam/saml"
)

// The InResponseTo an Assertion reports comes from a bearer confirmation
// that passes every check package saml makes, its Address included: another
// confirmation, from another client address, may name another request.
func TestNewAssertionInResponseToChecksAddress(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	confirmation := func(inResponseTo, address string) saml.SubjectConfirmation {
		return saml.SubjectConfirmation{
			Method: bearerMethod,
			SubjectConfirmationData: &saml.SubjectConfirmationData{
				Recipient:    "https://sp.example.com/acs",
				InResponseTo: inResponseTo,
				Address:      address,
				NotOnOrAfter: now.Add(time.Minute),
			},
		}
	}
	a := &saml.Assertion{Subject: &saml.Subject{SubjectConfirmations: []saml.SubjectConfirmation{
		confirmation("id-other", "198.51.100.7"),
		confirmation("id-mine", "192.0.2.1"),
	}}}
	check := bearerCheck{
		recipient: "https://sp.example.com/acs", start: now, end: now,
		address: func(d *saml.SubjectConfirmationData) bool { return d.Address == "192.0.2.1" },
	}
	if got := newAssertion(a, "", []string{"id-other", "id-mine"}, check).InResponseTo; got != "id-mine" {
		t.Errorf("InResponseTo = %q, want id-mine", got)
	}
}
