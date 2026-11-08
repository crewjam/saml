package samlidp

import (
	"encoding/xml"
	"testing"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
)

// TestExtensionsRoundTrip checks that the extension elements of a request
// are kept as standalone XML, with the namespaces declared outside them,
// and restored by samlRequest (saml-core §3.2.1).
func TestExtensionsRoundTrip(t *testing.T) {
	const requestXML = `<samlp:AuthnRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:ex="urn:example:ext" xmlns:other="urn:example:other" ID="id-1" Version="2.0" IssueInstant="2015-12-01T01:57:09Z">` +
		`<samlp:Extensions xmlns="urn:example:default">` +
		`<ex:Hint other:lang="en"><Inner>value</Inner><ex:Local xmlns:ex="urn:example:local"/></ex:Hint>` +
		`<ex:Second/>` +
		`</samlp:Extensions>` +
		`</samlp:AuthnRequest>`
	var q saml.AuthnRequest
	if err := xml.Unmarshal([]byte(requestXML), &q); err != nil {
		t.Fatal(err)
	}
	ireq := &saml.IdpAuthnRequest{Request: q, ACSEndpoint: &saml.IndexedEndpoint{}}
	req := newAuthnRequest(ireq)
	if len(req.Extensions) != 2 {
		t.Fatalf("Extensions = %q", req.Extensions)
	}

	check := func(t *testing.T, hint *etree.Element) {
		t.Helper()
		if hint.Tag != "Hint" || hint.NamespaceURI() != "urn:example:ext" {
			t.Fatalf("got %s in %s", hint.FullTag(), hint.NamespaceURI())
		}
		// Prefixes may be renamed; namespaces are kept.
		var attr *etree.Attr
		for i := range hint.Attr {
			if hint.Attr[i].Key == "lang" {
				attr = &hint.Attr[i]
			}
		}
		if attr == nil || attr.NamespaceURI() != "urn:example:other" || attr.Value != "en" {
			t.Errorf("attribute = %+v", attr)
		}
		inner := hint.FindElement("./Inner")
		if inner == nil || inner.NamespaceURI() != "urn:example:default" || inner.Text() != "value" {
			t.Errorf("Inner = %+v", inner)
		}
		local := hint.FindElement("./Local")
		if local == nil || local.NamespaceURI() != "urn:example:local" {
			t.Errorf("Local = %+v", local)
		}
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(req.Extensions[0]); err != nil {
		t.Fatal(err)
	}
	check(t, doc.Root())

	restored, err := req.samlRequest()
	if err != nil {
		t.Fatal(err)
	}
	if restored.Extensions == nil || len(restored.Extensions.ChildElements()) != 2 {
		t.Fatalf("Extensions = %v", restored.Extensions)
	}
	// It survives being written and read again.
	buf, err := xml.Marshal(restored)
	if err != nil {
		t.Fatal(err)
	}
	var again saml.AuthnRequest
	if err := xml.Unmarshal(buf, &again); err != nil {
		t.Fatal(err)
	}
	if again.Extensions == nil || again.Extensions.NamespaceURI() != protocolNamespace {
		t.Fatalf("Extensions = %v in %s", again.Extensions, buf)
	}
	children := again.Extensions.ChildElements()
	if len(children) != 2 || children[1].Tag != "Second" || children[1].NamespaceURI() != "urn:example:ext" {
		t.Fatalf("got %s", buf)
	}
	check(t, children[0])

	// Without extensions, there is no Extensions element.
	req.Extensions = nil
	if restored, err := req.samlRequest(); err != nil || restored.Extensions != nil {
		t.Fatalf("got %v, %v", restored.Extensions, err)
	}
	// One that is not XML is an error.
	req.Extensions = [][]byte{[]byte("<unclosed")}
	if _, err := req.samlRequest(); err == nil {
		t.Fatal("want an error")
	}
}
