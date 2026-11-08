package samlidp_test

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

// decodeResponse returns the Response that msg posts.
func decodeResponse(t *testing.T, msg *samlidp.Message) *saml.Response {
	t.Helper()
	buf, err := base64.StdEncoding.DecodeString(msg.FormValues()["SAMLResponse"])
	if err != nil {
		t.Fatal(err)
	}
	var resp saml.Response
	if err := xml.Unmarshal(buf, &resp); err != nil {
		t.Fatal(err)
	}
	return &resp
}

// TestResponseClock checks that the Response is stamped by the clock of
// WithClock, in UTC, as Now reads it.
func TestResponseClock(t *testing.T) {
	keys(t)
	at := time.Now().Add(-3 * time.Minute).In(time.FixedZone("UTC+5", 5*60*60)).Truncate(time.Millisecond)
	p := newPair(t, []samlidp.Option{samlidp.WithClock(dsig.NewFakeClockAt(at))}, nil)
	if now := p.idp.Now(); !now.Equal(at) || now.Location() != time.UTC {
		t.Fatalf("Now = %v, want %v in UTC", now, at)
	}
	ctx := context.Background()
	req, err := p.idp.IDPInitiated(ctx, spEntityID, "")
	if err != nil {
		t.Fatal(err)
	}
	subject := testSubject
	subject.AuthnInstant = at.Add(-time.Minute)
	msg, err := p.idp.Response(ctx, req, subject)
	if err != nil {
		t.Fatal(err)
	}
	resp := decodeResponse(t, msg)
	if !resp.IssueInstant.Equal(at) {
		t.Errorf("IssueInstant = %v, want %v", resp.IssueInstant, at)
	}
	if resp.Assertion == nil || !resp.Assertion.IssueInstant.Equal(at) {
		t.Errorf("assertion = %+v", resp.Assertion)
	}
}

// spNameQualifier is an AuthnOption that asks for the NameID to be in
// the namespace q.
func spNameQualifier(q string) samlsp.AuthnOption {
	return samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		if req.NameIDPolicy == nil {
			req.NameIDPolicy = &saml.NameIDPolicy{}
		}
		req.NameIDPolicy.SPNameQualifier = &q
		return nil
	})
}

func TestSPNameQualifier(t *testing.T) {
	const affiliation = "urn:example:affiliation"
	ctx := context.Background()

	// The SP's own entity ID needs no affiliation.
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, spNameQualifier(spEntityID))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.Response(ctx, req, testSubject); err != nil {
		t.Fatal(err)
	}

	// Another is refused, by default.
	_, req, err = p.parse(t, spNameQualifier(affiliation))
	status := asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)
	if req == nil || req.SPNameQualifier != affiliation {
		t.Fatalf("got %+v", req)
	}
	if _, err := p.idp.ErrorResponse(ctx, req, status); err != nil {
		t.Fatal(err)
	}
	_, err = p.idp.Response(ctx, req, testSubject)
	_ = asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)

	// WithAffiliation allows the affiliations of the SP.
	var asked []string
	member := func(_ context.Context, sp, aff string) (bool, error) {
		asked = append(asked, sp+" "+aff)
		return sp == spEntityID && aff == affiliation, nil
	}
	p = newPair(t, []samlidp.Option{samlidp.WithAffiliation(member)}, nil)
	_, req, err = p.parse(t, spNameQualifier(affiliation))
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.idp.Response(ctx, req, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	if a := decodeResponse(t, msg).Assertion; a == nil || a.Subject.NameID.SPNameQualifier != affiliation {
		t.Fatalf("assertion %+v", a)
	}
	if len(asked) != 2 || asked[0] != spEntityID+" "+affiliation {
		t.Fatalf("asked %q", asked)
	}
	req.SPNameQualifier = "urn:example:other"
	_, err = p.idp.Response(ctx, req, testSubject)
	_ = asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)

	// Its error is returned.
	boom := errors.New("boom")
	p = newPair(t, []samlidp.Option{samlidp.WithAffiliation(func(context.Context, string, string) (bool, error) { return false, boom })}, nil)
	if _, req, err = p.parse(t, spNameQualifier(affiliation)); !errors.Is(err, boom) || req != nil {
		t.Fatalf("got %+v, %v", req, err)
	}
}
