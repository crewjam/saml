package saml

import (
	"errors"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// With ClientAddress set, a bearer SubjectConfirmationData Address must
// name the client's address (saml-core §2.4.1.2), compared as an IP
// address. Without ClientAddress, or without Address, nothing is checked.
func TestSubjectConfirmationDataAddress(t *testing.T) {
	e := spcovSetup(t)
	parse := func(t *testing.T, clientAddress, address string) error {
		t.Helper()
		a := e.assertion()
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Address = address
		r := e.response()
		r.Assertion = a
		sp := *e.sp
		sp.ClientAddress = clientAddress
		_, err := sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, sp.AcsURL)
		return err
	}

	for _, tc := range []struct{ client, address string }{
		{"", "192.0.2.1"},                            // off by default
		{"192.0.2.1", ""},                            // no Address
		{"192.0.2.1", "192.0.2.1"},                   // same
		{"192.0.2.1:54321", "192.0.2.1"},             // RemoteAddr form
		{"::ffff:192.0.2.1", "192.0.2.1"},            // IPv4-mapped IPv6
		{"192.0.2.1", "::ffff:192.0.2.1"},            // and the other way round
		{"2001:db8::1", "2001:0DB8:0:0::0001"},       // IPv6 spellings
		{"[2001:db8::1]:443", "2001:db8::1"},         // IPv6 with port
		{"fe80::1%eth0", "fe80::1"},                  // zone ignored
		{"192.0.2.1", " 192.0.2.1 "},                 // xs:string whitespace
		{"client.example.com", "client.example.com"}, // not an IP address: exact
	} {
		assert.Check(t, parse(t, tc.client, tc.address), "client %q, Address %q", tc.client, tc.address)
	}

	for _, tc := range []struct{ client, address string }{
		{"192.0.2.2", "192.0.2.1"},
		{"192.0.2.1:54321", "192.0.2.2"},
		{"2001:db8::2", "2001:db8::1"},
		{"192.0.2.1", "client.example.com"},
		{"client.example.com", "CLIENT.example.com"},
		{"192.0.2.1", "192.0.2.1:80"},
	} {
		err := parse(t, tc.client, tc.address)
		assert.Check(t, errors.Is(err, ErrDestinationMismatch), "client %q, Address %q: %v", tc.client, tc.address, err)
		assert.Check(t, is.ErrorContains(spcovPrivateErr(t, err), "is not the client address"))
	}
}

// One bearer confirmation that passes is enough: a second confirmation
// whose Address matches confirms the subject even when the first does not.
func TestSubjectConfirmationDataAddressAnyConfirmation(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	first := a.Subject.SubjectConfirmations[0]
	data := *first.SubjectConfirmationData
	data.Address = "192.0.2.9"
	first.SubjectConfirmationData = &data
	second := a.Subject.SubjectConfirmations[0]
	data2 := *second.SubjectConfirmationData
	data2.Address = "192.0.2.1"
	second.SubjectConfirmationData = &data2
	a.Subject.SubjectConfirmations = []SubjectConfirmation{first, second}

	r := e.response()
	r.Assertion = a
	sp := *e.sp
	sp.ClientAddress = "192.0.2.1"
	_, err := sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, sp.AcsURL)
	assert.Check(t, err)
}
