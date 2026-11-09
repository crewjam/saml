package samlsp_test

import (
	"errors"
	"fmt"
	"testing"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

const (
	keyIDP   = "https://idp.example.com/"
	keySP    = "https://sp.example.com/"
	persist  = string(saml.PersistentNameIDFormat)
	otherIDP = "https://other-idp.example.com/"
)

// persistentAssertion returns an Assertion from keyIDP to keySP whose
// persistent NameID is "abc", with no qualifiers.
func persistentAssertion() *samlsp.Assertion {
	return &samlsp.Assertion{
		Issuer:     keyIDP,
		SPEntityID: keySP,
		NameID:     saml.NameID{Format: persist, Value: "abc"},
		Subject:    "abc",
	}
}

func mustSubjectKey(t *testing.T, a *samlsp.Assertion) string {
	t.Helper()
	k, err := a.SubjectKey()
	if err != nil {
		t.Fatalf("SubjectKey: %v", err)
	}
	return k
}

func TestSubjectKeyGolden(t *testing.T) {
	// These keys may be stored by applications; they must never change.
	for _, tc := range []struct {
		a    *samlsp.Assertion
		want string
	}{
		{
			persistentAssertion(),
			"samlsp-subject-v1:24:https://idp.example.com/:24:https://idp.example.com/:23:https://sp.example.com/:52:urn:oasis:names:tc:SAML:2.0:nameid-format:persistent:3:abc",
		},
		{
			&samlsp.Assertion{
				Issuer:     keyIDP,
				SPEntityID: keySP,
				NameID: saml.NameID{
					NameQualifier:   "urn:example:nq",
					SPNameQualifier: "urn:example:affiliation",
					Value:           "é:1",
				},
			},
			"samlsp-subject-v1:24:https://idp.example.com/:14:urn:example:nq:23:urn:example:affiliation:53:urn:oasis:names:tc:SAML:1.1:nameid-format:unspecified:4:é:1",
		},
	} {
		if got := mustSubjectKey(t, tc.a); got != tc.want {
			t.Errorf("SubjectKey =\n%s\nwant\n%s", got, tc.want)
		}
	}
}

func TestSubjectKeyDefaults(t *testing.T) {
	omitted := persistentAssertion()
	explicit := persistentAssertion()
	explicit.NameID.NameQualifier = keyIDP
	explicit.NameID.SPNameQualifier = keySP
	explicit.NameID.SPProvidedID = "alias" // not part of the name
	if a, b := mustSubjectKey(t, omitted), mustSubjectKey(t, explicit); a != b {
		t.Errorf("omitted qualifiers give %s, explicit ones %s", a, b)
	}

	pa, _ := omitted.SubjectKeyParts()
	pb, _ := explicit.SubjectKeyParts()
	want := samlsp.SubjectKeyParts{Issuer: keyIDP, NameQualifier: keyIDP, SPNameQualifier: keySP, Format: persist, Value: "abc"}
	if pa != want || pb != want {
		t.Errorf("SubjectKeyParts = %+v and %+v, want %+v", pa, pb, want)
	}

	noFormat := persistentAssertion()
	noFormat.NameID.Format = ""
	unspecified := persistentAssertion()
	unspecified.NameID.Format = string(saml.UnspecifiedNameIDFormat)
	if a, b := mustSubjectKey(t, noFormat), mustSubjectKey(t, unspecified); a != b {
		t.Errorf("omitted Format gives %s, unspecified %s", a, b)
	}
}

func TestSubjectKeyDistinguishes(t *testing.T) {
	base := persistentAssertion()
	variants := map[string]func(a *samlsp.Assertion){
		"other IdP":             func(a *samlsp.Assertion) { a.Issuer = otherIDP },
		"other IdP, same NQ":    func(a *samlsp.Assertion) { a.Issuer = otherIDP; a.NameID.NameQualifier = keyIDP },
		"other NameQualifier":   func(a *samlsp.Assertion) { a.NameID.NameQualifier = "urn:example:nq" },
		"other SPNameQualifier": func(a *samlsp.Assertion) { a.NameID.SPNameQualifier = "urn:example:affiliation" },
		"other SP":              func(a *samlsp.Assertion) { a.SPEntityID = "https://sp2.example.com/" },
		"other Format":          func(a *samlsp.Assertion) { a.NameID.Format = string(saml.EmailAddressNameIDFormat) },
		"other value":           func(a *samlsp.Assertion) { a.NameID.Value = "abd" },
		"value case":            func(a *samlsp.Assertion) { a.NameID.Value = "ABC" },
	}
	seen := map[string]string{mustSubjectKey(t, base): "base"}
	for name, change := range variants {
		a := persistentAssertion()
		change(a)
		k := mustSubjectKey(t, a)
		if prev, ok := seen[k]; ok {
			t.Errorf("%s has the same key as %s: %s", name, prev, k)
		}
		seen[k] = name
	}
}

func TestSubjectKeyUnambiguous(t *testing.T) {
	// Moving the boundary between fields, with values that contain the
	// separator and look like lengths, must change the key.
	cases := []samlsp.SubjectKeyParts{
		{Issuer: "a", NameQualifier: "b:1:c", SPNameQualifier: "d", Format: "f", Value: "v"},
		{Issuer: "a:5:b", NameQualifier: "c", SPNameQualifier: "d", Format: "f", Value: "v"},
		{Issuer: "a", NameQualifier: "b", SPNameQualifier: "1:c:1:d", Format: "f", Value: "v"},
		{Issuer: "a", NameQualifier: "b", SPNameQualifier: "c", Format: "d:1:f", Value: "v"},
		{Issuer: "a", NameQualifier: "b", SPNameQualifier: "c", Format: "d", Value: "f:1:v"},
		{Issuer: "a:1:b", NameQualifier: "", SPNameQualifier: "c", Format: "d", Value: "f:1:v"},
		{Issuer: "", NameQualifier: "a", SPNameQualifier: "b", Format: "c", Value: "d"},
		{Issuer: "a", NameQualifier: "b", SPNameQualifier: "c", Format: "d", Value: ""},
	}
	seen := map[string]int{}
	for i, p := range cases {
		k := p.Key()
		if j, ok := seen[k]; ok {
			t.Errorf("parts %d and %d share the key %s", j, i, k)
		}
		seen[k] = i
	}
}

func TestSubjectKeyRefused(t *testing.T) {
	base := etree.NewElement("saml:BaseID")
	base.SetText("E-1234")
	for name, a := range map[string]*samlsp.Assertion{
		"transient": {Issuer: keyIDP, SPEntityID: keySP, NameID: saml.NameID{Format: string(saml.TransientNameIDFormat), Value: "_abc"}},
		"BaseID":    {Issuer: keyIDP, SPEntityID: keySP, BaseID: base},
		"no NameID": {Issuer: keyIDP, SPEntityID: keySP},
		"no Issuer": {SPEntityID: keySP, NameID: saml.NameID{Format: persist, Value: "abc"}},
		"no SP":     {Issuer: keyIDP, NameID: saml.NameID{Format: persist, Value: "abc"}},
	} {
		if k, err := a.SubjectKey(); !errors.Is(err, samlsp.ErrNoSubjectKey) {
			t.Errorf("%s: SubjectKey = %q, %v; want ErrNoSubjectKey", name, k, err)
		}
		if _, err := a.SubjectKeyParts(); !errors.Is(err, samlsp.ErrNoSubjectKey) {
			t.Errorf("%s: SubjectKeyParts err = %v; want ErrNoSubjectKey", name, err)
		}
	}

	// An SPNameQualifier makes SPEntityID unnecessary.
	a := &samlsp.Assertion{Issuer: keyIDP, NameID: saml.NameID{SPNameQualifier: keySP, Format: persist, Value: "abc"}}
	if got, want := mustSubjectKey(t, a), mustSubjectKey(t, persistentAssertion()); got != want {
		t.Errorf("SubjectKey = %s, want %s", got, want)
	}
}

func TestSubjectKeyParseResponse(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti)
	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	a, err := cfg.ParseResponse(t.Context(), login(t, ti, msg), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
	}
	if a.SPEntityID != spEntityID {
		t.Errorf("SPEntityID = %q, want %q", a.SPEntityID, spEntityID)
	}
	p, err := a.SubjectKeyParts()
	if err != nil {
		t.Fatalf("SubjectKeyParts: %v", err)
	}
	want := samlsp.SubjectKeyParts{
		Issuer:          "https://idp.example.com/metadata",
		NameQualifier:   "https://idp.example.com/metadata",
		SPNameQualifier: spEntityID,
		Format:          string(saml.EmailAddressNameIDFormat),
		Value:           "alice@example.com",
	}
	if p != want {
		t.Errorf("SubjectKeyParts = %+v, want %+v", p, want)
	}
}

func ExampleAssertion_SubjectKey() {
	assertion := &samlsp.Assertion{ // as returned by ParseResponse
		Issuer:     "https://idp.example.com/metadata",
		SPEntityID: "https://sp.example.com/saml/metadata",
		NameID: saml.NameID{
			Format: string(saml.PersistentNameIDFormat),
			Value:  "a7f3c2e9",
		},
	}
	key, err := assertion.SubjectKey()
	if errors.Is(err, samlsp.ErrNoSubjectKey) {
		// For example, a transient NameID: identify the user by an
		// attribute instead, or ask the IdP for a persistent NameID
		// with samlsp.WithNameIDFormat.
		return
	}
	fmt.Println(key) // look up the user's account by key
	// Output:
	// samlsp-subject-v1:32:https://idp.example.com/metadata:32:https://idp.example.com/metadata:36:https://sp.example.com/saml/metadata:52:urn:oasis:names:tc:SAML:2.0:nameid-format:persistent:8:a7f3c2e9
}
