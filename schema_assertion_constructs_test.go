package saml

import (
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// assertionConstructsXML is an assertion with an Advice (saml-core §2.6),
// an AuthnContextDecl and an AuthzDecisionStatement (§2.7.4) with Evidence,
// children in schema order.
const assertionConstructsXML = `<saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ` +
	`xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" ID="id-outer" Version="2.0" IssueInstant="2030-01-01T00:00:00Z">` +
	`<saml:Issuer>https://idp.example.com/</saml:Issuer>` +
	`<saml:Advice>` +
	`<saml:AssertionIDRef>id-ref</saml:AssertionIDRef>` +
	`<saml:AssertionURIRef>https://idp.example.com/a/1</saml:AssertionURIRef>` +
	`<saml:Assertion ID="id-inner" Version="2.0" IssueInstant="2030-01-01T00:00:00Z"><saml:Issuer>https://other.example.com/</saml:Issuer></saml:Assertion>` +
	`<saml:EncryptedAssertion><xenc:EncryptedData xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"/></saml:EncryptedAssertion>` +
	`<x:Note xmlns:x="urn:example:advice" Level="1">hello</x:Note>` +
	`</saml:Advice>` +
	`<saml:AuthnStatement AuthnInstant="2030-01-01T00:00:00Z">` +
	`<saml:AuthnContext>` +
	`<saml:AuthnContextClassRef>urn:oasis:names:tc:SAML:2.0:ac:classes:Password</saml:AuthnContextClassRef>` +
	`<saml:AuthnContextDecl xmlns:ac="urn:oasis:names:tc:SAML:2.0:ac" xsi:type="ac:AuthnContextDeclarationBaseType">` +
	`<ac:AuthnMethod><ac:Authenticator><ac:RestrictedPassword/></ac:Authenticator></ac:AuthnMethod>` +
	`</saml:AuthnContextDecl>` +
	`<saml:AuthenticatingAuthority>https://authority.example.com/</saml:AuthenticatingAuthority>` +
	`</saml:AuthnContext>` +
	`</saml:AuthnStatement>` +
	`<saml:AuthzDecisionStatement Resource="https://sp.example.com/doc" Decision="Permit">` +
	`<saml:Action Namespace="urn:oasis:names:tc:SAML:1.0:action:rwedc">Read</saml:Action>` +
	`<saml:Action>Write</saml:Action>` +
	`<saml:Evidence>` +
	`<saml:AssertionIDRef>id-evidence</saml:AssertionIDRef>` +
	`<saml:Assertion ID="id-evidence-inner" Version="2.0" IssueInstant="2030-01-01T00:00:00Z"><saml:Issuer>https://other.example.com/</saml:Issuer></saml:Assertion>` +
	`</saml:Evidence>` +
	`</saml:AuthzDecisionStatement>` +
	`</saml:Assertion>`

func checkAssertionConstructs(t *testing.T, a *Assertion) {
	t.Helper()
	assert.Assert(t, a.Advice != nil)
	assert.Check(t, is.DeepEqual(a.Advice.AssertionIDRefs, []string{"id-ref"}))
	assert.Check(t, is.DeepEqual(a.Advice.AssertionURIRefs, []string{"https://idp.example.com/a/1"}))
	assert.Assert(t, is.Len(a.Advice.Assertions, 1))
	assert.Check(t, is.Equal(a.Advice.Assertions[0].ID, "id-inner"))
	assert.Check(t, is.Equal(a.Advice.Assertions[0].Issuer.Value, "https://other.example.com/"))
	assert.Assert(t, is.Len(a.Advice.EncryptedAssertions, 1))
	assert.Check(t, is.Equal(a.Advice.EncryptedAssertions[0].Tag, "EncryptedAssertion"))
	assert.Check(t, is.Equal(a.Advice.EncryptedAssertions[0].NamespaceURI(), samlAssertionNamespace))
	assert.Check(t, a.Advice.EncryptedAssertions[0].FindElement("./EncryptedData") != nil)
	assert.Assert(t, is.Len(a.Advice.Other, 1))
	assert.Check(t, is.Equal(a.Advice.Other[0].Tag, "Note"))
	assert.Check(t, is.Equal(a.Advice.Other[0].NamespaceURI(), "urn:example:advice"))
	assert.Check(t, is.Equal(a.Advice.Other[0].Text(), "hello"))

	assert.Assert(t, is.Len(a.AuthnStatements, 1))
	ac := a.AuthnStatements[0].AuthnContext
	assert.Assert(t, ac.AuthnContextClassRef != nil)
	assert.Check(t, is.Equal(ac.AuthnContextClassRef.Value, "urn:oasis:names:tc:SAML:2.0:ac:classes:Password"))
	assert.Assert(t, ac.AuthnContextDecl != nil)
	assert.Check(t, is.Equal(ac.AuthnContextDecl.Tag, "AuthnContextDecl"))
	assert.Check(t, is.Equal(ac.AuthnContextDecl.NamespaceURI(), samlAssertionNamespace))
	// xmlns:xsi is declared on the Assertion, so the attribute may have
	// another prefix, bound to the same namespace.
	var xsiType *etree.Attr
	for i, attr := range ac.AuthnContextDecl.Attr {
		if attr.Key == "type" && attr.NamespaceURI() == xsiNamespaceURI {
			xsiType = &ac.AuthnContextDecl.Attr[i]
		}
	}
	assert.Assert(t, xsiType != nil, elementToString(ac.AuthnContextDecl))
	assert.Check(t, is.Equal(xsiType.Value, "ac:AuthnContextDeclarationBaseType"))
	restricted := ac.AuthnContextDecl.FindElement("./AuthnMethod/Authenticator/RestrictedPassword")
	assert.Assert(t, restricted != nil)
	assert.Check(t, is.Equal(restricted.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:ac"))
	assert.Check(t, is.Nil(ac.AuthnContextDeclRef))
	assert.Check(t, is.DeepEqual(ac.AuthenticatingAuthorities, []AuthenticatingAuthority{{Value: "https://authority.example.com/"}}))

	assert.Assert(t, is.Len(a.AuthzDecisionStatements, 1))
	ads := a.AuthzDecisionStatements[0]
	assert.Check(t, is.Equal(ads.Resource, "https://sp.example.com/doc"))
	assert.Check(t, is.Equal(ads.Decision, AuthzDecisionPermit))
	assert.Check(t, is.DeepEqual(ads.Actions, []Action{
		{Namespace: "urn:oasis:names:tc:SAML:1.0:action:rwedc", Value: "Read"},
		{Value: "Write"},
	}))
	assert.Assert(t, ads.Evidence != nil)
	assert.Check(t, is.DeepEqual(ads.Evidence.AssertionIDRefs, []string{"id-evidence"}))
	assert.Assert(t, is.Len(ads.Evidence.Assertions, 1))
	assert.Check(t, is.Equal(ads.Evidence.Assertions[0].ID, "id-evidence-inner"))
}

// Advice, AuthnContextDecl and AuthzDecisionStatement are read, and written
// back (by MarshalXML and by Element) so that they read the same again. The
// output passes the round-trip validation every received message passes.
func TestAssertionConstructsRoundTrip(t *testing.T) {
	var a Assertion
	assert.NilError(t, xml.Unmarshal([]byte(assertionConstructsXML), &a))
	checkAssertionConstructs(t, &a)

	marshalled, err := xml.Marshal(a)
	assert.NilError(t, err)
	assert.Check(t, xmlroundtrip.Validate(marshalled))
	var b Assertion
	assert.NilError(t, xml.Unmarshal(marshalled, &b), string(marshalled))
	checkAssertionConstructs(t, &b)

	el, err := a.CanonicalElement()
	assert.NilError(t, err)
	fromElement := spcovSerialize(t, el)
	assert.Check(t, xmlroundtrip.Validate(fromElement))
	var c Assertion
	assert.NilError(t, xml.Unmarshal(fromElement, &c), string(fromElement))
	checkAssertionConstructs(t, &c)

	// Through the untrusted path the SP reads assertions with.
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromBytes([]byte(assertionConstructsXML)))
	var d Assertion
	assert.NilError(t, unmarshalElement(doc.Root(), &d))
	checkAssertionConstructs(t, &d)
}

// The children are written in schema order: Advice after Conditions and
// before the statements (saml-core §2.3.3); in AuthnContext, the class
// reference, then the declaration or its reference, then the authorities
// (§2.7.2.2).
func TestAssertionConstructsSchemaOrder(t *testing.T) {
	now := time.Date(2030, 1, 1, 0, 0, 0, 0, time.UTC)
	decl := etree.NewElement("saml:AuthnContextDecl")
	decl.CreateAttr("xmlns:saml", samlAssertionNamespace)
	a := Assertion{
		ID: "id-a", Version: "2.0", IssueInstant: now,
		Issuer:     Issuer{Value: "https://idp.example.com/"},
		Subject:    &Subject{NameID: &NameID{Value: "alice"}},
		Conditions: &Conditions{NotOnOrAfter: now},
		Advice:     &Advice{AssertionIDRefs: []string{"id-ref"}},
		AuthnStatements: []AuthnStatement{{AuthnInstant: now, AuthnContext: AuthnContext{
			AuthnContextClassRef:      &AuthnContextClassRef{Value: "urn:class"},
			AuthnContextDeclRef:       &AuthnContextDeclRef{Value: "urn:decl"},
			AuthenticatingAuthorities: []AuthenticatingAuthority{{Value: "urn:authority"}},
		}}},
		AuthzDecisionStatements: []AuthzDecisionStatement{{Resource: "urn:r", Decision: AuthzDecisionDeny, Actions: []Action{{Value: "Read"}}}},
		AttributeStatements:     []AttributeStatement{{Attributes: []Attribute{{Name: "n"}}}},
	}
	order := func(t *testing.T, s string, names ...string) {
		t.Helper()
		last := -1
		for _, name := range names {
			i := strings.Index(s, name)
			assert.Check(t, i > last, "%s out of order in %s", name, s)
			last = i
		}
	}
	names := []string{"Issuer>", "Subject>", "Conditions", "Advice>", "AuthnStatement ", "AuthnContextClassRef>", "AuthnContextDeclRef>", "AuthenticatingAuthority>", "AuthzDecisionStatement ", "AttributeStatement>"}

	marshalled, err := xml.Marshal(a)
	assert.NilError(t, err)
	order(t, string(marshalled), names...)
	assert.Check(t, is.Contains(string(marshalled), `<AuthzDecisionStatement xmlns="urn:oasis:names:tc:SAML:2.0:assertion" Resource="urn:r" Decision="Deny">`))
	order(t, elementToString(a.Element()), names...)

	a.AuthnStatements[0].AuthnContext.AuthnContextDeclRef = nil
	a.AuthnStatements[0].AuthnContext.AuthnContextDecl = decl
	names[6] = "AuthnContextDecl"
	marshalled, err = xml.Marshal(a)
	assert.NilError(t, err)
	order(t, string(marshalled), names...)
	order(t, elementToString(a.Element()), names...)
}

// AuthnContextDeclRef is read and written.
func TestAuthnContextDeclRef(t *testing.T) {
	const in = `<AuthnContext xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<AuthnContextDeclRef>https://idp.example.com/decl</AuthnContextDeclRef>` +
		`</AuthnContext>`
	var ac AuthnContext
	assert.NilError(t, xml.Unmarshal([]byte(in), &ac))
	assert.Assert(t, ac.AuthnContextDeclRef != nil)
	assert.Check(t, is.Equal(ac.AuthnContextDeclRef.Value, "https://idp.example.com/decl"))
	assert.Check(t, is.Nil(ac.AuthnContextDecl))
	assert.Check(t, is.Nil(ac.AuthnContextClassRef))

	out, err := xml.Marshal(AuthnStatement{AuthnContext: ac})
	assert.NilError(t, err)
	var statement AuthnStatement
	assert.NilError(t, xml.Unmarshal(out, &statement))
	assert.Check(t, is.DeepEqual(statement.AuthnContext, ac))
	assert.Check(t, is.Equal(elementToString(ac.Element()),
		`<saml:AuthnContext><saml:AuthnContextDeclRef>https://idp.example.com/decl</saml:AuthnContextDeclRef></saml:AuthnContext>`))
}

// An assertion element in a foreign namespace inside Advice is not one of
// its Assertions, and a SAML element Advice does not allow is ignored.
func TestAdviceForeignAndUnknownChildren(t *testing.T) {
	const in = `<Advice xmlns="urn:oasis:names:tc:SAML:2.0:assertion">` +
		`<x:Assertion xmlns:x="urn:example:foreign" ID="id-foreign"/>` +
		`<Subject><NameID>mallory</NameID></Subject>` +
		`</Advice>`
	var a Advice
	assert.NilError(t, xml.Unmarshal([]byte(in), &a))
	assert.Check(t, is.Len(a.Assertions, 0))
	assert.Assert(t, is.Len(a.Other, 1))
	assert.Check(t, is.Equal(a.Other[0].SelectAttrValue("ID", ""), "id-foreign"))

	out, err := xml.Marshal(a)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(out), "mallory"), string(out))
	assert.Check(t, xmlroundtrip.Validate(out))
}

// The ServiceProvider returns the AuthnContextDecl of a signed assertion
// as the signature covers it.
func TestParseResponseKeepsAuthnContextDecl(t *testing.T) {
	e := spcovSetup(t)
	assertionEl := e.assertion().Element()
	decl := etree.NewElement("saml:AuthnContextDecl")
	decl.CreateAttr("xmlns:ac", "urn:oasis:names:tc:SAML:2.0:ac")
	decl.CreateElement("ac:AuthnMethod").CreateElement("ac:Authenticator").SetText("x")
	assertionEl.FindElement("./AuthnStatement/AuthnContext").AddChild(decl)
	signed := e.idpSign(t, assertionEl)

	assertion, err := e.parseAdviceResponse(t, signed, false)
	assert.NilError(t, err)
	got := assertion.AuthnStatements[0].AuthnContext.AuthnContextDecl
	assert.Assert(t, got != nil)
	authenticator := got.FindElement("./AuthnMethod/Authenticator")
	assert.Assert(t, authenticator != nil, elementToString(got))
	assert.Check(t, is.Equal(authenticator.NamespaceURI(), "urn:oasis:names:tc:SAML:2.0:ac"))
	assert.Check(t, is.Equal(authenticator.Text(), "x"))
}
