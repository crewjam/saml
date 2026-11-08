package samlidp_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/gob"
	"encoding/json"
	"encoding/xml"
	"errors"
	"reflect"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/xmlenc"
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

// TestRequestFields checks that the protocol fields of the request reach
// the AuthnRequest, and survive being kept with encoding/json and
// encoding/gob.
func TestRequestFields(t *testing.T) {
	p := newPair(t, nil, nil)
	proxyCount := 2
	_, req, err := p.parse(t, samlsp.WithAuthnRequest(func(req *saml.AuthnRequest) error {
		req.Consent = "urn:oasis:names:tc:SAML:2.0:consent:obtained"
		req.AttributeConsumingServiceIndex = "3"
		req.Scoping = &saml.Scoping{
			ProxyCount: &proxyCount,
			IDPList: &saml.IDPList{IDPEntries: []saml.IDPEntry{
				{ProviderID: idpEntityID, Name: "Example", Loc: "https://idp.example.com/saml/sso"},
			}},
			RequesterIDs: []string{"https://app.example.com"},
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	if req.Consent != "urn:oasis:names:tc:SAML:2.0:consent:obtained" || req.AttributeConsumingServiceIndex != "3" {
		t.Fatalf("got %+v", req)
	}
	s := req.Scoping
	if s == nil || s.ProxyCount == nil || *s.ProxyCount != 2 || s.IDPList == nil || len(s.IDPList.IDPEntries) != 1 ||
		s.IDPList.IDPEntries[0].ProviderID != idpEntityID || s.IDPList.IDPEntries[0].Loc != "https://idp.example.com/saml/sso" ||
		len(s.RequesterIDs) != 1 || s.RequesterIDs[0] != "https://app.example.com" {
		t.Fatalf("Scoping = %+v", s)
	}

	buf, err := json.Marshal(req)
	if err != nil {
		t.Fatal(err)
	}
	var fromJSON samlidp.AuthnRequest
	if err := json.Unmarshal(buf, &fromJSON); err != nil {
		t.Fatal(err)
	}
	var b bytes.Buffer
	if err := gob.NewEncoder(&b).Encode(req); err != nil {
		t.Fatal(err)
	}
	var fromGob samlidp.AuthnRequest
	if err := gob.NewDecoder(&b).Decode(&fromGob); err != nil {
		t.Fatal(err)
	}
	for name, kept := range map[string]*samlidp.AuthnRequest{"json": &fromJSON, "gob": &fromGob} {
		if !reflect.DeepEqual(kept.Scoping, req.Scoping) || kept.Consent != req.Consent ||
			kept.AttributeConsumingServiceIndex != req.AttributeConsumingServiceIndex || !kept.IssueInstant.Equal(req.IssueInstant) {
			t.Errorf("%s: kept %+v, want %+v", name, kept, req)
		}
		if _, err := p.idp.Response(context.Background(), kept, testSubject); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestForceAuthnInstant(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t, samlsp.ForceAuthn)
	if err != nil {
		t.Fatal(err)
	}
	// A login from an existing session is not a new authentication.
	subject := testSubject
	subject.AuthnInstant = req.IssueInstant.Add(-saml.MaxClockSkew - time.Second)
	_, err = p.idp.Response(context.Background(), req, subject)
	var status *saml.StatusError
	if err == nil || errors.As(err, &status) {
		t.Fatalf("got %v, want an error for the application", err)
	}
	// Within the clock skew, it is.
	subject.AuthnInstant = req.IssueInstant.Add(-saml.MaxClockSkew + time.Second)
	if _, err := p.idp.Response(context.Background(), req, subject); err != nil {
		t.Fatal(err)
	}
}

func TestEncryptedNameIDFormat(t *testing.T) {
	const encrypted = saml.NameIDFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:encrypted")

	// The SP cannot be sent an encrypted assertion.
	p := newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(encrypted)})
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	if req.NameIDFormat != encrypted {
		t.Fatalf("NameIDFormat = %q", req.NameIDFormat)
	}
	_, err = p.idp.Response(context.Background(), req, testSubject)
	_ = asStatus(t, err, saml.StatusRequester, saml.StatusInvalidNameIDPolicy)

	// It can: the NameID is issued as an EncryptedID (saml-core §8.3.9),
	// in the encrypted assertion, which the SP decrypts.
	p = newPair(t, nil, []samlsp.Option{samlsp.WithNameIDFormat(encrypted), samlsp.WithEncryptionKey(spKey, spCert)})
	ctx := context.Background()
	msg, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.idp.Response(ctx, req, testSubject)
	if err != nil {
		t.Fatal(err)
	}
	// The participant, for single logout, has the plaintext NameID.
	if resp.Participant == nil || resp.Participant.NameID.Value != testSubject.NameID || resp.Participant.NameID.Format != string(saml.TransientNameIDFormat) {
		t.Fatalf("Participant = %+v", resp.Participant)
	}
	encryptedData := decodeResponse(t, resp).EncryptedAssertion.FindElement("./EncryptedData")
	if encryptedData == nil {
		t.Fatal("the assertion is not encrypted")
	}
	plaintext, err := xmlenc.Decrypt(spKey, encryptedData)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(plaintext); err != nil {
		t.Fatal(err)
	}
	if doc.Root().FindElement("./Subject/NameID") != nil || doc.Root().FindElement("./Subject/EncryptedID/EncryptedData") == nil {
		t.Fatalf("the assertion's Subject has no EncryptedID: %s", plaintext)
	}
	a, err := p.sp.ParseResponse(ctx, postForm(t, resp.Destination, formOf(t, resp)), samlsp.WithRequestID(msg.ID))
	if err != nil {
		t.Fatal(err)
	}
	if a.Subject != testSubject.NameID || a.NameID.Format != string(saml.TransientNameIDFormat) {
		t.Fatalf("got %+v", a)
	}
}
