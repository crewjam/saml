package samlidp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

var (
	pairwiseKey      = bytes.Repeat([]byte{1}, samlidp.MinPairwiseKeySize)
	otherPairwiseKey = bytes.Repeat([]byte{2}, samlidp.MinPairwiseKeySize)
)

func TestTransientNameID(t *testing.T) {
	keys(t)
	c, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert))
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for range 1000 {
		id := c.TransientNameID()
		b, err := base64.RawURLEncoding.DecodeString(id)
		if err != nil || len(b) < 16 {
			t.Fatalf("TransientNameID() = %q: %d bytes, %v", id, len(b), err)
		}
		if seen[id] {
			t.Fatalf("TransientNameID() repeated %q", id)
		}
		seen[id] = true
	}

	// It reads from the source of WithRand.
	r := bytes.NewReader(bytes.Repeat([]byte{0xff}, 20))
	c, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert), samlidp.WithRand(r))
	if err != nil {
		t.Fatal(err)
	}
	if id := c.TransientNameID(); id != strings.Repeat("_", 26)+"8" {
		t.Fatalf("TransientNameID() = %q", id)
	}
	func() {
		defer func() {
			if recover() == nil {
				t.Error("TransientNameID did not panic when the source of random bytes failed")
			}
		}()
		c.TransientNameID()
	}()
}

func TestPairwiseNameID(t *testing.T) {
	const sp1, sp2 = "https://sp1.example.com/saml", "https://sp2.example.com/saml"
	a := samlidp.PairwiseNameID(pairwiseKey, "alice", sp1)
	if b, err := base64.RawURLEncoding.DecodeString(a); err != nil || len(b) != 32 {
		t.Fatalf("PairwiseNameID = %q: %d bytes, %v", a, len(b), err)
	}
	if strings.Contains(a, "alice") {
		t.Fatalf("PairwiseNameID = %q reveals the user ID", a)
	}
	if got := samlidp.PairwiseNameID(pairwiseKey, "alice", sp1); got != a {
		t.Errorf("PairwiseNameID is not stable: %q, then %q", a, got)
	}
	for name, got := range map[string]string{
		"another SP":   samlidp.PairwiseNameID(pairwiseKey, "alice", sp2),
		"another user": samlidp.PairwiseNameID(pairwiseKey, "bob", sp1),
		"another key":  samlidp.PairwiseNameID(otherPairwiseKey, "alice", sp1),
	} {
		if got == a {
			t.Errorf("%s gets the same NameID %q", name, got)
		}
	}

	// The inputs are length-prefixed: moving characters from one to the
	// other, or swapping them, changes the NameID.
	seen := map[string]string{}
	for _, in := range [][2]string{
		{"ab", "c"}, {"a", "bc"}, {"abc", ""}, {"", "abc"}, {"c", "ab"},
		{"a\x00", "bc"}, {"a", "\x00bc"},
		{"a\x00\x00\x00\x00\x00\x00\x00\x01b", ""},
		{"a", "b"}, {"b", "a"},
	} {
		got := samlidp.PairwiseNameID(pairwiseKey, in[0], in[1])
		if prev, ok := seen[got]; ok {
			t.Errorf("PairwiseNameID(%q, %q) = PairwiseNameID(%s)", in[0], in[1], prev)
		}
		seen[got] = strings.Join([]string{in[0], in[1]}, ", ")
	}

	defer func() {
		if recover() == nil {
			t.Error("PairwiseNameID accepted a short key")
		}
	}()
	samlidp.PairwiseNameID(pairwiseKey[:samlidp.MinPairwiseKeySize-1], "alice", sp1)
}

func TestPairwiseNameIDFor(t *testing.T) {
	keys(t)
	ctx := context.Background()
	const (
		affiliation = "urn:example:affiliation"
		member2     = "https://member2.example.com/saml"
	)
	member := func(_ context.Context, sp, aff string) (bool, error) {
		return (sp == spEntityID || sp == member2) && aff == affiliation, nil
	}
	c, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert), samlidp.WithAffiliation(member))
	if err != nil {
		t.Fatal(err)
	}
	nameID := func(req *samlidp.AuthnRequest) string {
		t.Helper()
		id, err := c.PairwiseNameIDFor(ctx, req, pairwiseKey, "alice")
		if err != nil {
			t.Fatal(err)
		}
		return id
	}

	// Without an SPNameQualifier, or with the SP's own entity ID, it is
	// the NameID of the SP.
	own := nameID(&samlidp.AuthnRequest{ServiceProvider: spEntityID})
	if own != samlidp.PairwiseNameID(pairwiseKey, "alice", spEntityID) {
		t.Errorf("NameID %q is not that of the SP", own)
	}
	if got := nameID(&samlidp.AuthnRequest{ServiceProvider: spEntityID, SPNameQualifier: spEntityID}); got != own {
		t.Errorf("with its own entity ID as SPNameQualifier, the SP gets %q, not %q", got, own)
	}
	if got := nameID(&samlidp.AuthnRequest{ServiceProvider: member2}); got == own {
		t.Errorf("another SP gets the same NameID %q", got)
	}

	// Members of an affiliation that ask for it get the same NameID, that
	// of the affiliation.
	aff1 := nameID(&samlidp.AuthnRequest{ServiceProvider: spEntityID, SPNameQualifier: affiliation})
	aff2 := nameID(&samlidp.AuthnRequest{ServiceProvider: member2, SPNameQualifier: affiliation})
	if aff1 != aff2 || aff1 != samlidp.PairwiseNameID(pairwiseKey, "alice", affiliation) || aff1 == own {
		t.Errorf("affiliation NameIDs %q and %q", aff1, aff2)
	}

	// An SP that is not a member is refused.
	_, err = c.PairwiseNameIDFor(ctx, &samlidp.AuthnRequest{ServiceProvider: "https://other.example.com", SPNameQualifier: affiliation}, pairwiseKey, "alice")
	_ = asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)

	// The error of WithAffiliation is returned.
	boom := errors.New("boom")
	c, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert),
		samlidp.WithAffiliation(func(context.Context, string, string) (bool, error) { return false, boom }))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.PairwiseNameIDFor(ctx, &samlidp.AuthnRequest{ServiceProvider: spEntityID, SPNameQualifier: affiliation}, pairwiseKey, "alice"); !errors.Is(err, boom) {
		t.Fatalf("got %v", err)
	}

	// An IdP that does not enforce the NameIDPolicy ignores the
	// SPNameQualifier, as Response does.
	c, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert),
		samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.EnforceNameIDPolicy = false }))
	if err != nil {
		t.Fatal(err)
	}
	if got := nameID(&samlidp.AuthnRequest{ServiceProvider: spEntityID, SPNameQualifier: affiliation}); got != own {
		t.Errorf("without NameIDPolicy enforcement, the SP gets %q, not its own %q", got, own)
	}
}

// SetNameID gives an SP that asks for transient NameIDs a new one at each
// login, and otherwise a pairwise persistent NameID, qualified by the
// affiliation the SP asks for; the SP accepts both.
func TestSetNameID(t *testing.T) {
	ctx := context.Background()
	login := func(p *pair, opts ...samlsp.AuthnOption) *saml.NameID {
		t.Helper()
		_, req, err := p.parse(t, opts...)
		if err != nil {
			t.Fatal(err)
		}
		subject := testSubject
		if err := p.idp.SetNameID(ctx, req, &subject, pairwiseKey, "alice"); err != nil {
			t.Fatal(err)
		}
		msg, err := p.idp.Response(ctx, req, subject)
		if err != nil {
			t.Fatal(err)
		}
		a := decodeResponse(t, msg).Assertion
		if a == nil || a.Subject == nil || a.Subject.NameID == nil {
			t.Fatalf("assertion %+v", a)
		}
		return a.Subject.NameID
	}

	// x/samlsp asks for transient NameIDs by default.
	p := newPair(t, nil, nil)
	n1, n2 := login(p), login(p)
	if n1.Format != string(saml.TransientNameIDFormat) || n1.Value == n2.Value || n1.Value == "alice" {
		t.Fatalf("transient NameIDs %+v, %+v", n1, n2)
	}

	p = newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(saml.PersistentNameIDFormat)})
	n1, n2 = login(p), login(p)
	want := samlidp.PairwiseNameID(pairwiseKey, "alice", spEntityID)
	if n1.Format != string(saml.PersistentNameIDFormat) || n1.Value != want || n2.Value != want || n1.SPNameQualifier != spEntityID {
		t.Fatalf("persistent NameIDs %+v, %+v", n1, n2)
	}

	// With no format asked for, the NameID is persistent too.
	p = newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(saml.UnspecifiedNameIDFormat)})
	if n := login(p); n.Format != string(saml.PersistentNameIDFormat) || n.Value != want {
		t.Fatalf("NameID %+v", n)
	}

	const affiliation = "urn:example:affiliation"
	member := func(_ context.Context, sp, aff string) (bool, error) {
		return sp == spEntityID && aff == affiliation, nil
	}
	p = newPair(t, []samlidp.Option{samlidp.WithAffiliation(member)}, []samlsp.Option{samlsp.WithNameIDFormat(saml.PersistentNameIDFormat)})
	n := login(p, spNameQualifier(affiliation))
	if n.Value != samlidp.PairwiseNameID(pairwiseKey, "alice", affiliation) || n.SPNameQualifier != affiliation {
		t.Fatalf("affiliation NameID %+v", n)
	}
}
