package saml

import (
	"encoding/xml"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

const authnExtensionsXML = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">` +
	`<saml:Issuer>https://sp.example.com/saml2/metadata</saml:Issuer>` +
	`<samlp:Extensions><ex:Hint xmlns:ex="urn:example:ext" lang="en">value</ex:Hint></samlp:Extensions>` +
	`<samlp:NameIDPolicy Format="urn:oasis:names:tc:SAML:2.0:nameid-format:transient"/>` +
	`</samlp:AuthnRequest>`

// authnExtensionsHint checks the ex:Hint element of el, a samlp:Extensions
// element.
func authnExtensionsHint(t *testing.T, el *etree.Element) {
	t.Helper()
	assert.Assert(t, el != nil)
	assert.Check(t, is.Equal("urn:oasis:names:tc:SAML:2.0:protocol", el.NamespaceURI()))
	assert.Check(t, is.Equal("Extensions", el.Tag))
	hint := el.FindElement("./Hint")
	assert.Assert(t, hint != nil)
	assert.Check(t, is.Equal("urn:example:ext", hint.NamespaceURI()))
	assert.Check(t, is.Equal("value", hint.Text()))
	assert.Check(t, is.Equal("en", hint.SelectAttrValue("lang", "")))
}

// saml-core-2.0-os §3.2.1: a request may carry samlp:Extensions, which
// AuthnRequest keeps, in schema order, through xml.Unmarshal, xml.Marshal
// and Element.
func TestAuthnRequestExtensionsRoundTrip(t *testing.T) {
	var req AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(authnExtensionsXML), &req))
	authnExtensionsHint(t, req.Extensions)
	assert.Assert(t, req.NameIDPolicy != nil)

	marshaled, err := xml.Marshal(req)
	assert.NilError(t, err)
	var again AuthnRequest
	assert.NilError(t, xml.Unmarshal(marshaled, &again))
	authnExtensionsHint(t, again.Extensions)
	assert.Assert(t, again.NameIDPolicy != nil)
	assert.Check(t, strings.Index(string(marshaled), "Extensions") < strings.Index(string(marshaled), "NameIDPolicy"), "%s", marshaled)

	doc := etree.NewDocument()
	doc.SetRoot(req.Element())
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	var fromElement AuthnRequest
	assert.NilError(t, xml.Unmarshal(buf, &fromElement))
	authnExtensionsHint(t, fromElement.Extensions)
	children := req.Element().ChildElements()
	assert.Assert(t, is.Len(children, 3))
	assert.Check(t, is.Equal("Extensions", children[1].Tag))

	// Without Extensions, none is written.
	req.Extensions = nil
	marshaled, err = xml.Marshal(req)
	assert.NilError(t, err)
	assert.Check(t, !strings.Contains(string(marshaled), "Extensions"), "%s", marshaled)
}

// The signature of a request covers its Extensions, which the IdP reads.
func TestIDPVerifiesSignatureOverAuthnRequestExtensions(t *testing.T) {
	test := newSignedAuthnRequestTest(t)
	authReq, err := test.SP.MakeAuthenticationRequest(test.IDP.SSOURL.String(), HTTPPostBinding, HTTPPostBinding)
	assert.NilError(t, err)
	var parsed AuthnRequest
	assert.NilError(t, xml.Unmarshal([]byte(authnExtensionsXML), &parsed))
	authReq.Extensions = parsed.Extensions
	authReq.Signature = nil
	assert.NilError(t, test.SP.SignAuthnRequest(authReq))

	req, err := validateAuthnRequest(t, test, postForm(t, authReq.Post("relay")))
	assert.NilError(t, err)
	assert.Check(t, req.RequestSigned)
	authnExtensionsHint(t, req.Request.Extensions)

	requestXML := string(spcovSerialize(t, authReq.Element()))
	tampered := strings.Replace(requestXML, ">value<", ">other<", 1)
	assert.Assert(t, tampered != requestXML)
	_, err = validateAuthnRequest(t, test, postRequestXML(t, test, tampered))
	assert.Check(t, errors.Is(err, ErrInvalidSignature), "%v", err)

	// And with the HTTP-Redirect binding.
	redirectURL, err := authReq.Redirect("relay", &test.SP)
	assert.NilError(t, err)
	r, _ := http.NewRequest(http.MethodGet, redirectURL.String(), nil)
	req, err = validateAuthnRequest(t, test, r)
	assert.NilError(t, err)
	authnExtensionsHint(t, req.Request.Extensions)
}
