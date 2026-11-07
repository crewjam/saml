package saml

import (
	"fmt"
	"runtime"
	"strings"
	"testing"

	"github.com/beevik/etree"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// namespaceDeclarations returns n namespace declarations, to make every
// namespace context built under them expensive to copy.
func namespaceDeclarations(n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		fmt.Fprintf(&b, ` xmlns:p%d="urn:p%d"`, i, i)
	}
	return b.String()
}

// parseCost parses buf as a response, which must fail, and returns the
// bytes allocated per byte of input and the private error.
func parseCost(t *testing.T, e *spcovEnv, buf []byte) (float64, error) {
	t.Helper()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
	runtime.ReadMemStats(&after)
	assert.Assert(t, err != nil)
	return float64(after.TotalAlloc-before.TotalAlloc) / float64(len(buf)), spcovPrivateErr(t, err)
}

// Before the fixes for findChildren and for unsigned responses with several
// assertions, the responses in these tests allocated about 20,000 bytes for
// each byte of input; parsing them now allocates a few hundred.
const maxParseBytesPerInputByte = 2000

const responseOpen = `<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" xmlns:ds="http://www.w3.org/2000/09/xmldsig#" ID="id-response" Version="2.0" IssueInstant="2014-01-01T00:00:00Z" InResponseTo="id-request" Destination="https://sp.example.com/saml/acs"`

const responseStatus = `<saml:Issuer>https://idp.example.com/metadata</saml:Issuer><samlp:Status><samlp:StatusCode Value="urn:oasis:names:tc:SAML:2.0:status:Success"/></samlp:Status>`

// Looking for the Signature among an element's children built the
// namespace context of every matching child from scratch, copying every
// declaration in scope: 2,000 declarations and 5,000 empty Signature
// elements (120 KB) took seconds and gigabytes.
func TestFindChildrenCostIndependentOfNamespaceDeclarations(t *testing.T) {
	e := spcovSetup(t)
	buf := []byte(responseOpen + namespaceDeclarations(2000) + ">" + responseStatus +
		strings.Repeat("<ds:Signature/>", 5000) + "</samlp:Response>")
	perByte, err := parseCost(t, e, buf)
	assert.Check(t, is.Error(err, "expected at most one http://www.w3.org/2000/09/xmldsig#:Signature element"))
	assert.Check(t, perByte < maxParseBytesPerInputByte, "allocated %.0f bytes per input byte", perByte)
}

// lookupElementNamespace must find what SubContext and LookupPrefix find,
// and checkNamespaceDeclarations must refuse what SubContext refuses.
func TestLookupElementNamespaceMatchesSubContext(t *testing.T) {
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(`<r xmlns="urn:default" xmlns:a="urn:a" xmlns:b="urn:b"><c>
  <x/><a:x/><b:x xmlns:b="urn:b2"/><x xmlns="urn:d2"/><x xmlns=""/><a:x xmlns:a="urn:a1" xmlns:a="urn:a2"/>
  <u:x/><x xmlns:xml="urn:not-xml"/><x xmlns:xml="http://www.w3.org/XML/1998/namespace"/>
  <x xmlns:xmlns="urn:x"/><x xmlns="http://www.w3.org/2000/xmlns/"/><xml:x/>
</c></r>`))
	parent := doc.Root().ChildElements()[0]
	parentCtx, err := etreeutils.NSBuildParentContext(parent.ChildElements()[0])
	assert.NilError(t, err)
	for _, el := range parent.ChildElements() {
		wantCtx, wantErr := parentCtx.SubContext(el)
		gotErr := checkNamespaceDeclarations(el)
		assert.Check(t, is.Equal(gotErr, wantErr), "%s", elementToString(el))
		if wantErr != nil {
			continue
		}
		want, wantErr := wantCtx.LookupPrefix(el.Space)
		got, gotErr := lookupElementNamespace(parentCtx, el)
		assert.Check(t, is.Equal(got, want), "%s", elementToString(el))
		assert.Check(t, is.Equal(gotErr == nil, wantErr == nil), "%s", elementToString(el))
	}
}
