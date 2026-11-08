package samlidp_test

import (
	"context"
	"encoding/base64"
	"errors"
	"testing"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/xmlenc"
)

// respond runs a login up to the IdP's Response, with opts, and returns
// the Response, its XML, and the SP's verdict on it.
func (p *pair) respond(t *testing.T, subject samlidp.Subject, opts ...samlidp.ResponseOption) (*samlidp.Message, *etree.Element, *samlsp.Assertion, error) {
	t.Helper()
	resp, root, a, err := p.tryRespond(t, subject, opts...)
	if resp == nil {
		t.Fatal(err)
	}
	return resp, root, a, err
}

// tryRespond is respond, but returns the error of Response, with a nil
// Message, instead of failing the test.
func (p *pair) tryRespond(t *testing.T, subject samlidp.Subject, opts ...samlidp.ResponseOption) (*samlidp.Message, *etree.Element, *samlsp.Assertion, error) {
	t.Helper()
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "relay-state")
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg))
	if err != nil {
		t.Fatal(err)
	}
	resp, err := p.idp.Response(ctx, req, subject, opts...)
	if err != nil {
		return nil, nil, nil, err
	}
	form := formOf(t, resp)
	raw, err := base64.StdEncoding.DecodeString(form.Get("SAMLResponse"))
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(raw); err != nil {
		t.Fatal(err)
	}
	a, err := p.sp.ParseResponse(ctx, postForm(t, resp.Destination, form), samlsp.WithRequestID(msg.ID))
	return resp, doc.Root(), a, err
}

func signed(el *etree.Element) bool {
	for _, c := range el.ChildElements() {
		if c.Tag == "Signature" {
			return true
		}
	}
	return false
}

// ResponseSigning chooses which of the Response and the assertion the IdP
// signs, and the SP accepts each.
func TestResponseSigning(t *testing.T) {
	for _, tc := range []struct {
		signing                      saml.ResponseSigning
		responseSigned, assertSigned bool
	}{
		{saml.SignResponseAndAssertion, true, true},
		{saml.SignAssertionOnly, false, true},
		{saml.SignResponseOnly, true, false},
	} {
		// The SP's metadata says WantAssertionsSigned="false", so that
		// SignResponseOnly is allowed to leave the assertion unsigned.
		p := newPairWithMetadata(t, []samlidp.Option{samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
			idp.ResponseSigning = tc.signing
		})}, nil, setWantAssertionsSigned(false))
		_, root, a, err := p.respond(t, testSubject)
		if err != nil {
			t.Fatalf("%v: the SP refused the Response: %v", tc.signing, errors.Unwrap(err))
		}
		if a.Subject != testSubject.NameID {
			t.Errorf("%v: subject %q", tc.signing, a.Subject)
		}
		assertion := root.FindElement("./Assertion")
		if assertion == nil {
			t.Fatalf("%v: no assertion", tc.signing)
		}
		if signed(root) != tc.responseSigned || signed(assertion) != tc.assertSigned {
			t.Errorf("%v: Response signed %v, assertion signed %v", tc.signing, signed(root), signed(assertion))
		}
	}
}

func setWantAssertionsSigned(want bool) func(*saml.EntityDescriptor) {
	return func(md *saml.EntityDescriptor) {
		for i := range md.SPSSODescriptors {
			md.SPSSODescriptors[i].WantAssertionsSigned = &want
		}
	}
}

// SignResponseOnly still signs the assertion for an SP whose metadata
// says WantAssertionsSigned="true" (saml-metadata §2.4.4).
func TestSignResponseOnlyHonorsWantAssertionsSigned(t *testing.T) {
	p := newPairWithMetadata(t, []samlidp.Option{samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
		idp.ResponseSigning = saml.SignResponseOnly
	})}, nil, setWantAssertionsSigned(true))
	_, root, _, err := p.respond(t, testSubject)
	if err != nil {
		t.Fatalf("the SP refused the Response: %v", errors.Unwrap(err))
	}
	if !signed(root) || !signed(root.FindElement("./Assertion")) {
		t.Fatalf("Response signed %v, assertion signed %v", signed(root), signed(root.FindElement("./Assertion")))
	}
}

// An assertion encrypted with AES-CBC in an unsigned Response is what
// Entra ID sends with token encryption; x/samlsp refuses it by default.
func TestSignAssertionOnlyWithCBC(t *testing.T) {
	keys(t)
	idpOpts := []samlidp.Option{samlidp.EnableInsecureAESCBC, samlidp.EnableInsecureRSAOAEPSHA1, samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) {
		idp.ResponseSigning = saml.SignAssertionOnly
		enc := xmlenc.OAEP()
		enc.BlockCipher = xmlenc.AES256CBC
		idp.AssertionEncrypter = enc
	})}
	p := newPair(t, idpOpts, []samlsp.Option{samlsp.WithEncryptionKey(spKey, spCert)})
	_, root, _, err := p.respond(t, testSubject)
	if root.FindElement("./EncryptedAssertion") == nil || signed(root) {
		t.Fatal("not an encrypted assertion in an unsigned Response")
	}
	if err == nil {
		t.Fatal("the SP accepted AES-CBC in an unsigned Response")
	}

	relaxed := newPair(t, idpOpts, []samlsp.Option{
		samlsp.WithEncryptionKey(spKey, spCert),
		samlsp.WithServiceProvider(func(sp *saml.ServiceProvider) { sp.RequireSignedResponseForCBC = false }),
	})
	if _, _, _, err := relaxed.respond(t, testSubject); err != nil {
		t.Fatalf("relaxed SP refused: %v", errors.Unwrap(err))
	}
}

// Message.Participant names the session as the SP received it, so that
// single logout names it too, even when WithAssertion changed it.
func TestParticipantSessionIndexFromAssertion(t *testing.T) {
	p := newPair(t, nil, nil)
	resp, _, a, err := p.respond(t, testSubject, samlidp.WithAssertion(func(a *saml.Assertion) error {
		a.AuthnStatements[0].SessionIndex = "_" + a.ID
		return nil
	}))
	if err != nil {
		t.Fatal(errors.Unwrap(err))
	}
	if len(a.SessionIndexes) != 1 || a.SessionIndexes[0] != "_"+a.ID {
		t.Fatalf("SP got SessionIndexes %v", a.SessionIndexes)
	}
	if resp.Participant == nil || resp.Participant.SessionIndex != a.SessionIndexes[0] {
		t.Fatalf("Participant %+v, SP got %v", resp.Participant, a.SessionIndexes)
	}
}
