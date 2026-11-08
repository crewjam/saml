package saml

import (
	"net/netip"
	"strings"
)

// subjectConfirmationAddressMatches reports whether address, the Address of
// a SubjectConfirmationData (saml-core §2.4.1.2: the network address from
// which the attesting entity may present the assertion), names the same IP
// address as client, the address of the user agent that presented it (see
// ServiceProvider.ClientAddress).
//
// Both are compared as IP addresses where they parse as one, so that
// different spellings of an address match: "2001:db8::1" and
// "2001:0db8:0:0::1", or "192.0.2.1" and "::ffff:192.0.2.1". A port on
// client ("192.0.2.1:1234" or "[2001:db8::1]:1234", as in
// http.Request.RemoteAddr) and an IPv6 zone are ignored; address, which
// saml-core describes as an IPv4 or IPv6 address, may not have a port. An
// address that is not an IP address must match exactly.
func subjectConfirmationAddressMatches(address, client string) bool {
	address = trimXMLWhitespace(address)
	client = strings.TrimSpace(client)
	a, aErr := parseIP(address, false)
	c, cErr := parseIP(client, true)
	if aErr != nil || cErr != nil {
		return aErr != nil && cErr != nil && address == client
	}
	return a == c
}

// parseIP parses s as an IP address or, if withPort, also as an IP
// address and port, returning the address without zone and with an
// IPv4-mapped IPv6 address as IPv4.
func parseIP(s string, withPort bool) (netip.Addr, error) {
	addr, err := netip.ParseAddr(s)
	if err != nil {
		if !withPort {
			return netip.Addr{}, err
		}
		addrPort, portErr := netip.ParseAddrPort(s)
		if portErr != nil {
			return netip.Addr{}, err
		}
		addr = addrPort.Addr()
	}
	return addr.WithZone("").Unmap(), nil
}
