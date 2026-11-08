package slo_test

import (
	"encoding/base64"
	"errors"
	"net/url"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
)

// failedLogoutResponse returns a LogoutResponse form from ti, signed with
// ti's key, that answers inResponseTo with the status Responder.
func failedLogoutResponse(t *testing.T, ti *testIDP, inResponseTo string) url.Values {
	t.Helper()
	resp := &saml.LogoutResponse{
		ID: "id-failed-" + inResponseTo, Version: "2.0", IssueInstant: time.Now().UTC(), Destination: spSLOURL,
		InResponseTo: inResponseTo,
		Issuer:       &saml.Issuer{Format: "urn:oasis:names:tc:SAML:2.0:nameid-format:entity", Value: ti.idp.Metadata().EntityID},
		Status:       saml.Status{StatusCode: saml.StatusCode{Value: saml.StatusResponder}},
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: ti.key, Certificate: [][]byte{ti.cert.Raw}})
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signer.SignEnveloped(resp.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return url.Values{"SAMLResponse": {base64.StdEncoding.EncodeToString(buf)}}
}

// A LogoutResponse whose status is not Success must still answer one of
// the pending requests, and is accepted only once.
func TestFailedLogoutResponseChecked(t *testing.T) {
	ti := newTestIDP(t)
	_, s := newService(t, ti, nil)

	other := failedLogoutResponse(t, ti, "id-some-other-request")
	if _, err := s.ParseResponse(t.Context(), postForm(spSLOURL, other), "id-pending"); !errors.Is(err, saml.ErrRequestIDMismatch) {
		t.Fatalf("a failed response to another request: %v, want saml.ErrRequestIDMismatch", err)
	}

	mine := failedLogoutResponse(t, ti, "id-pending")
	if _, err := s.ParseResponse(t.Context(), postForm(spSLOURL, mine), "id-pending"); !errors.Is(err, saml.ErrBadStatus{Status: saml.StatusResponder}) {
		t.Fatalf("first delivery: %v, want saml.ErrBadStatus", err)
	}
	if _, err := s.ParseResponse(t.Context(), postForm(spSLOURL, mine), "id-pending"); !errors.Is(err, saml.ErrAssertionReplayed) {
		t.Fatalf("second delivery: %v, want saml.ErrAssertionReplayed", err)
	}
}
