package slo_test

import (
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp/slo"
)

func TestRequestMatches(t *testing.T) {
	const idp = "https://idp.example.com/metadata"
	alice := saml.NameID{Value: "alice"}
	req := &slo.Request{Issuer: idp, NameID: alice, SessionIndexes: []string{"s1", "s2"}}
	for _, tc := range []struct {
		name    string
		issuer  string
		nameID  saml.NameID
		indexes []string
		want    bool
	}{
		{"named session", idp, alice, []string{"s2"}, true},
		{"one of several sessions", idp, alice, []string{"s0", "s1"}, true},
		{"another session of the user", idp, alice, []string{"s3"}, false},
		{"no session index", idp, alice, nil, false},
		{"another user", idp, saml.NameID{Value: "mallory"}, []string{"s1"}, false},
		{"another IdP's user of the same name", "https://other.example.com/metadata", alice, []string{"s1"}, false},
	} {
		if got := req.Matches(tc.issuer, tc.nameID, tc.indexes); got != tc.want {
			t.Errorf("%s: Matches = %v", tc.name, got)
		}
	}

	all := &slo.Request{Issuer: idp, NameID: alice}
	if !all.Matches(idp, alice, []string{"any"}) || !all.Matches(idp, alice, nil) {
		t.Error("a request without SessionIndexes does not match all of the user's sessions")
	}
	if (&slo.Request{Issuer: idp}).Matches(idp, saml.NameID{}, nil) {
		t.Error("a request without a NameID (such as a BaseID) matches a session without one")
	}
}
