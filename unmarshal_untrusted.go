package saml

import (
	"fmt"

	"github.com/beevik/etree"
)

// xsiNamespaceURI is the XML Schema instance namespace, which xsi:type is in.
const xsiNamespaceURI = "http://www.w3.org/2001/XMLSchema-instance"

// sanitizeAttributesForUnmarshal rewrites root, in place, so that
// encoding/xml cannot read an attribute field from anything other than the
// unqualified attribute of that name.
//
// A struct field tagged `xml:"Name,attr"` matches an attribute with local
// name Name in any namespace, and encoding/xml reports a namespace
// declaration xmlns:Name="..." as such an attribute (in the "xmlns" space).
// When several match, the last one wins. Exclusive canonicalization drops
// declarations that nothing uses, so a declaration added to a signed element
// leaves the signature valid yet replaces the value of the attribute it is
// named after. A namespace in the tag cannot prevent this: encoding/xml has
// no way to ask for the empty namespace only.
//
// So every namespace prefix declared in the tree that could be the name of
// an attribute field is renamed to a generated one (ns0, ns1, ...), and
// every namespace-qualified attribute is dropped except those in the xml
// and xsi namespaces, which some fields read by namespace (xsi:type,
// xml:lang). The attribute fields of the protocol and assertion types are
// all named after exported Go fields, so they start with an upper case
// letter (TestUnmarshalledAttributeFieldsStartUpperCase checks this); a
// prefix that starts with a lower case ASCII letter, as the prefixes real
// documents use do (saml, samlp, ds, xs, ...), is kept. Element and
// attribute names keep their namespaces, so what encoding/xml reads is
// otherwise unchanged. Prefixes inside attribute values and text (such as
// the "xs" in xsi:type="xs:string") are left as written.
//
// root must already carry, as declarations, any namespaces it inherits from
// its ancestors (see elementToBytes).
func sanitizeAttributesForUnmarshal(root *etree.Element) {
	used := map[string]bool{}
	var collect func(el *etree.Element)
	collect = func(el *etree.Element) {
		used[el.Space] = true
		for _, attr := range el.Attr {
			used[attr.Space] = true
			if attr.Space == "xmlns" {
				used[attr.Key] = true
			}
		}
		for _, child := range el.ChildElements() {
			collect(child)
		}
	}
	collect(root)

	next := 0
	generate := func() string {
		for {
			prefix := fmt.Sprintf("ns%d", next)
			next++
			if !used[prefix] {
				return prefix
			}
		}
	}

	type binding struct{ prefix, uri string }
	var walk func(el *etree.Element, scope map[string]binding)
	walk = func(el *etree.Element, scope map[string]binding) {
		inScope, copied := scope, false
		for _, attr := range el.Attr {
			if attr.Space != "xmlns" || attr.Key == "xml" || attr.Key == "xmlns" {
				continue
			}
			if !copied {
				inScope, copied = make(map[string]binding, len(scope)+1), true
				for k, v := range scope {
					inScope[k] = v
				}
			}
			prefix := attr.Key
			if !safeNamespacePrefix(prefix) {
				prefix = generate()
			}
			inScope[attr.Key] = binding{prefix: prefix, uri: attr.Value}
		}

		if b, ok := inScope[el.Space]; ok {
			el.Space = b.prefix
		}

		attrs := make([]etree.Attr, 0, len(el.Attr))
		for _, attr := range el.Attr {
			switch attr.Space {
			case "":
				// unqualified attributes and the default namespace declaration
			case "xml":
				// the reserved prefix; it cannot be redeclared
			case "xmlns":
				b, ok := inScope[attr.Key]
				if !ok {
					// xmlns:xml or xmlns:xmlns: drop
					continue
				}
				attr.Key = b.prefix
			default:
				b, ok := inScope[attr.Space]
				if !ok || (b.uri != xsiNamespaceURI && b.uri != xmlNamespaceURI) {
					continue
				}
				attr.Space = b.prefix
			}
			attrs = append(attrs, attr)
		}
		el.Attr = attrs

		for _, child := range el.ChildElements() {
			walk(child, inScope)
		}
	}
	walk(root, map[string]binding{})
}

// safeNamespacePrefix reports whether prefix cannot be the name of an
// attribute field of the protocol and assertion types, all of which start
// with an upper case letter.
func safeNamespacePrefix(prefix string) bool {
	return prefix != "" && prefix[0] >= 'a' && prefix[0] <= 'z'
}
