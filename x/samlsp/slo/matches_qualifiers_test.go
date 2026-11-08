package slo_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp/slo"
)

// signLogoutRequest returns req signed with ti's key.
func signLogoutRequest(t *testing.T, ti *testIDP, req *saml.LogoutRequest) []byte {
	t.Helper()
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signer.SignEnveloped(req.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// TestRequestMatchesQualifiers checks that Matches compares the Format,
// NameQualifier and SPNameQualifier of the NameIDs too, taking an omitted
// one as its default: unspecified, the IdP and this SP (saml-core §2.2.2,
// §8.3).
func TestRequestMatchesQualifiers(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)
	idp := ti.idp.Metadata().EntityID
	persistent := string(saml.PersistentNameIDFormat)
	affiliation := "https://affiliation.example.com"
	for i, tc := range []struct {
		name          string
		request, held saml.NameID
		want          bool
	}{
		{"same, unqualified", saml.NameID{Format: persistent, Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, true},
		{"same, qualified", saml.NameID{Format: persistent, NameQualifier: idp, SPNameQualifier: spEntityID, Value: "a"}, saml.NameID{Format: persistent, NameQualifier: idp, SPNameQualifier: spEntityID, Value: "a"}, true},
		{"request qualified with the defaults", saml.NameID{Format: persistent, NameQualifier: idp, SPNameQualifier: spEntityID, Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, true},
		{"session qualified with the defaults", saml.NameID{Format: persistent, Value: "a"}, saml.NameID{Format: persistent, NameQualifier: idp, SPNameQualifier: spEntityID, Value: "a"}, true},
		{"omitted format is unspecified", saml.NameID{Value: "a"}, saml.NameID{Format: string(saml.UnspecifiedNameIDFormat), Value: "a"}, true},
		{"another format", saml.NameID{Format: string(saml.EmailAddressNameIDFormat), Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, false},
		{"format omitted on one side only", saml.NameID{Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, false},
		{"another NameQualifier", saml.NameID{Format: persistent, NameQualifier: "https://other.example.com", Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, false},
		{"another SPNameQualifier", saml.NameID{Format: persistent, SPNameQualifier: affiliation, Value: "a"}, saml.NameID{Format: persistent, Value: "a"}, false},
		{"session in an affiliation", saml.NameID{Format: persistent, Value: "a"}, saml.NameID{Format: persistent, SPNameQualifier: affiliation, Value: "a"}, false},
		{"same affiliation", saml.NameID{Format: persistent, SPNameQualifier: affiliation, Value: "a"}, saml.NameID{Format: persistent, SPNameQualifier: affiliation, Value: "a"}, true},
	} {
		req, _ := idpLogoutRequest(t, ti)
		req.ID = "id-qualifiers-" + string(rune('a'+i))
		nameID := tc.request
		req.NameID = &nameID
		buf := signLogoutRequest(t, ti, req)
		got, err := s.ParseRequest(t.Context(), postForm(spSLOURL, url.Values{"SAMLRequest": {base64.StdEncoding.EncodeToString(buf)}}))
		if err != nil {
			t.Fatalf("%s: ParseRequest: %v (%v)", tc.name, err, errors.Unwrap(err))
		}
		if m := got.Matches(idp, tc.held, []string{"index-1"}); m != tc.want {
			t.Errorf("%s: Matches = %v", tc.name, m)
		}
	}

	// A Request made by hand knows no SP entity ID: an omitted
	// SPNameQualifier matches only an omitted one.
	byHand := &slo.Request{Issuer: idp, NameID: saml.NameID{Value: "a", SPNameQualifier: spEntityID}}
	if byHand.Matches(idp, saml.NameID{Value: "a"}, nil) {
		t.Error("a hand-made Request matched an SPNameQualifier against an omitted one")
	}
}
