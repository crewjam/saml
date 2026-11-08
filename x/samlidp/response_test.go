package samlidp_test

import (
	"context"
	"encoding/base64"
	"encoding/xml"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
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
