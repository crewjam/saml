package samlidp_test

import (
	"context"
	"errors"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// A Subject with no NameIDFormat is asserted with the unspecified format,
// with no qualifiers, not as a transient NameID: the IdP does not know
// that NameID is a one-time identifier.
func TestDefaultNameIDFormatIsUnspecified(t *testing.T) {
	p := newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(saml.UnspecifiedNameIDFormat)})
	subject := testSubject
	subject.NameIDFormat = ""
	a, _ := p.login(t, nil, subject)
	if a.NameID.Format != string(saml.UnspecifiedNameIDFormat) || a.NameID.Value != subject.NameID {
		t.Fatalf("NameID = %+v", a.NameID)
	}
	if a.NameID.NameQualifier != "" || a.NameID.SPNameQualifier != "" {
		t.Fatalf("an unspecified NameID is qualified: %+v", a.NameID)
	}

	// The IdP metadata says so too, unless WithNameIDFormats says
	// otherwise.
	d := p.idp.Metadata().IDPSSODescriptors[0]
	if len(d.NameIDFormats) != 1 || d.NameIDFormats[0] != saml.UnspecifiedNameIDFormat {
		t.Fatalf("metadata NameIDFormats = %v", d.NameIDFormats)
	}
}

// An SP that asks for transient NameIDs, as one of x/samlsp does by
// default, is not sent the default format as if it were transient: the
// request is refused with InvalidNameIDPolicy.
func TestDefaultNameIDFormatTransientRequest(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject
	subject.NameIDFormat = ""
	_, err = p.idp.Response(context.Background(), req, subject)
	var status *saml.StatusError
	if !errors.As(err, &status) || status.SecondLevel != saml.StatusInvalidNameIDPolicy {
		t.Fatalf("got %v", err)
	}
}
