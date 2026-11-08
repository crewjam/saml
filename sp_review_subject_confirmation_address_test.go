package saml

import (
	"encoding/base64"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// A bearer SubjectConfirmationData Address must name the client's address
// (saml-core §2.4.1.2), compared as an IP address. Without a client
// address, or without Address, nothing is checked.
func TestSubjectConfirmationDataAddress(t *testing.T) {
	e := spcovSetup(t)
	parse := func(t *testing.T, clientAddress, address string) error {
		t.Helper()
		a := e.assertion()
		a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Address = address
		r := e.response()
		r.Assertion = a
		sp := *e.sp
		sp.clientAddress = clientAddress
		_, err := sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, sp.AcsURL)
		return err
	}

	for _, tc := range []struct{ client, address string }{
		{"", "192.0.2.1"},                            // no client address
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
	sp.clientAddress = "192.0.2.1"
	_, err := sp.ParseXMLResponse(spcovSerialize(t, e.idpSign(t, r.Element())), []string{spcovRequestID}, sp.AcsURL)
	assert.Check(t, err)
}

// ParseResponse takes the client address from ClientAddress, or from the
// request's RemoteAddr when ClientAddress is nil, and a ClientAddress that
// returns "" turns the check off.
func TestParseResponseClientAddress(t *testing.T) {
	e := spcovSetup(t)
	a := e.assertion()
	data := *a.Subject.SubjectConfirmations[0].SubjectConfirmationData
	data.Address = "192.0.2.1"
	a.Subject.SubjectConfirmations[0].SubjectConfirmationData = &data
	r := e.response()
	r.Assertion = a
	body := spcovSerialize(t, e.idpSign(t, r.Element()))

	parse := func(t *testing.T, remoteAddr string, clientAddress func(*http.Request) string) error {
		t.Helper()
		form := url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(body)}}
		req := httptest.NewRequest(http.MethodPost, e.sp.AcsURL.String(), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = remoteAddr
		assert.NilError(t, req.ParseForm())
		sp := *e.sp
		sp.ClientAddress = clientAddress
		_, err := sp.ParseResponse(req, []string{spcovRequestID})
		return err
	}
	fromHeader := func(req *http.Request) string { return req.Header.Get("X-Test-Client") }

	assert.Check(t, parse(t, "192.0.2.1:54321", nil))
	err := parse(t, "198.51.100.7:54321", nil)
	assert.Check(t, errors.Is(err, ErrDestinationMismatch), "%v", err)
	assert.Check(t, parse(t, "198.51.100.7:54321", fromHeader)) // header empty: not checked
	assert.Check(t, parse(t, "198.51.100.7:54321", func(*http.Request) string { return "192.0.2.1" }))
	err = parse(t, "192.0.2.1:54321", func(*http.Request) string { return "203.0.113.5" })
	assert.Check(t, errors.Is(err, ErrDestinationMismatch), "%v", err)
}

// ConfirmsClientAddress makes the same Address check as ParseResponse.
func TestConfirmsClientAddress(t *testing.T) {
	sp := &ServiceProvider{}
	req := httptest.NewRequest(http.MethodPost, "/acs", nil)
	req.RemoteAddr = "192.0.2.1:54321"
	data := func(address string) *SubjectConfirmationData { return &SubjectConfirmationData{Address: address} }

	assert.Check(t, sp.ConfirmsClientAddress(nil, req))
	assert.Check(t, sp.ConfirmsClientAddress(data(""), req))
	assert.Check(t, sp.ConfirmsClientAddress(data("192.0.2.1"), req))
	assert.Check(t, !sp.ConfirmsClientAddress(data("192.0.2.2"), req))

	sp.ClientAddress = func(*http.Request) string { return "" }
	assert.Check(t, sp.ConfirmsClientAddress(data("192.0.2.2"), req))
	sp.ClientAddress = func(*http.Request) string { return "192.0.2.2" }
	assert.Check(t, sp.ConfirmsClientAddress(data("192.0.2.2"), req))
	assert.Check(t, !sp.ConfirmsClientAddress(data("192.0.2.1"), req))
}
