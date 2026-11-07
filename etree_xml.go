package saml

import (
	"encoding/xml"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// xmlNamespaceURI is the namespace bound to the reserved "xml" prefix.
const xmlNamespaceURI = "http://www.w3.org/XML/1998/namespace"

// etreeElementXML lets encoding/xml read and write an element, such as a
// ds:Signature, held as an *etree.Element.
//
// encoding/xml cannot handle *etree.Element itself: it marshals the struct's
// fields (<Space>, <Tag>, ...) and unmarshals any element into an empty
// etree.Element. Types with such a field shadow it with this type in their
// MarshalXML and UnmarshalXML methods. The shadowing field must have exactly
// the same tag as the field it shadows (for Signature, `xml:"Signature"`,
// with no namespace), or encoding/xml keeps both.
//
// Namespace prefixes are kept as written, not rewritten as encoding/xml would.
// Exclusive canonicalization includes prefixes, so rewriting them would make
// the signature's SignedInfo canonicalize differently and the signature fail.
type etreeElementXML etree.Element

// MarshalXML implements xml.Marshaler.
func (s *etreeElementXML) MarshalXML(e *xml.Encoder, _ xml.StartElement) error {
	return encodeEtreeElement(e, (*etree.Element)(s), nil)
}

// encodeEtreeElement writes el to e with its prefixes intact. scope holds the
// prefixes declared by the ancestors already written ("" is the default
// namespace); a prefix that el uses but is declared outside the subtree being
// written is looked up on el's real ancestors and declared on el.
func encodeEtreeElement(e *xml.Encoder, el *etree.Element, scope map[string]bool) error {
	declared := make(map[string]bool, len(scope)+2)
	for prefix := range scope {
		declared[prefix] = true
	}

	start := xml.StartElement{Name: xml.Name{Local: qualifiedName(el.Space, el.Tag)}}
	for _, attr := range el.Attr {
		start.Attr = append(start.Attr, xml.Attr{
			Name:  xml.Name{Local: qualifiedName(attr.Space, attr.Key)},
			Value: attr.Value,
		})
		switch {
		case attr.Space == "xmlns":
			declared[attr.Key] = true
		case attr.Space == "" && attr.Key == "xmlns":
			declared[""] = true
		}
	}

	// Declare the prefixes el and its attributes use but do not have in
	// scope, so the output never depends on namespaces declared on elements
	// that are not written.
	if !declared[el.Space] {
		start.Attr = append(start.Attr, namespaceDeclaration(el.Space, el.NamespaceURI()))
		declared[el.Space] = true
	}
	for i := range el.Attr {
		attr := &el.Attr[i]
		if attr.Space == "" || attr.Space == "xmlns" || declared[attr.Space] {
			continue
		}
		start.Attr = append(start.Attr, namespaceDeclaration(attr.Space, attr.NamespaceURI()))
		declared[attr.Space] = true
	}

	if err := e.EncodeToken(start); err != nil {
		return err
	}
	for _, child := range el.Child {
		var err error
		switch child := child.(type) {
		case *etree.Element:
			err = encodeEtreeElement(e, child, declared)
		case *etree.CharData:
			err = e.EncodeToken(xml.CharData(child.Data))
		case *etree.Comment:
			err = e.EncodeToken(xml.Comment(child.Data))
		}
		if err != nil {
			return err
		}
	}
	return e.EncodeToken(start.End())
}

func qualifiedName(prefix, local string) string {
	if prefix == "" {
		return local
	}
	return prefix + ":" + local
}

// xmlnsAttrName returns the attribute name that declares prefix: "xmlns"
// for the default namespace (prefix ""), "xmlns:<prefix>" otherwise.
func xmlnsAttrName(prefix string) string {
	if prefix == "" {
		return "xmlns"
	}
	return "xmlns:" + prefix
}

func namespaceDeclaration(prefix, uri string) xml.Attr {
	return xml.Attr{Name: xml.Name{Local: xmlnsAttrName(prefix)}, Value: uri}
}

// UnmarshalXML implements xml.Unmarshaler.
func (s *etreeElementXML) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	el, err := decodeEtreeElement(d, start, nil)
	if err != nil {
		return err
	}
	*s = etreeElementXML(*el)
	return nil
}

// decodeEtreeElement builds an etree element from start and the tokens up to
// its end.
//
// xml.Decoder replaces prefixes with namespace URIs, so each prefix is
// recovered from the declarations in scope (scope maps prefix to URI; ""
// is the default namespace). A namespace declared outside the element, such
// as xmlns:ds on an EntityDescriptor, cannot be recovered that way; it gets
// the prefix "ds" for XML Signature, or a generated one otherwise, and a
// declaration on the element.
func decodeEtreeElement(d *xml.Decoder, start xml.StartElement, scope map[string]string) (*etree.Element, error) {
	inScope := make(map[string]string, len(scope)+2)
	for prefix, uri := range scope {
		inScope[prefix] = uri
	}
	for _, attr := range start.Attr {
		switch {
		case attr.Name.Space == "xmlns":
			inScope[attr.Name.Local] = attr.Value
		case attr.Name.Space == "" && attr.Name.Local == "xmlns":
			inScope[""] = attr.Value
		}
	}

	var extraDecls []xml.Attr
	prefixFor := func(uri string, allowDefault bool) string {
		if uri == "" {
			return ""
		}
		if uri == xmlNamespaceURI {
			return "xml"
		}
		if allowDefault {
			if defaultURI, ok := inScope[""]; ok && defaultURI == uri {
				return ""
			}
		}
		for prefix, scopeURI := range inScope {
			if prefix != "" && scopeURI == uri {
				return prefix
			}
		}
		prefix := ""
		if _, taken := inScope["ds"]; uri == dsig.Namespace && !taken {
			prefix = "ds"
		}
		for i := 0; prefix == ""; i++ {
			if _, taken := inScope[fmt.Sprintf("ns%d", i)]; !taken {
				prefix = fmt.Sprintf("ns%d", i)
			}
		}
		inScope[prefix] = uri
		extraDecls = append(extraDecls, namespaceDeclaration(prefix, uri))
		return prefix
	}

	el := etree.NewElement(qualifiedName(prefixFor(start.Name.Space, true), start.Name.Local))
	for _, attr := range start.Attr {
		prefix := attr.Name.Space
		if prefix != "xmlns" {
			prefix = prefixFor(attr.Name.Space, false)
		}
		el.CreateAttr(qualifiedName(prefix, attr.Name.Local), attr.Value)
	}
	for _, decl := range extraDecls {
		el.CreateAttr(decl.Name.Local, decl.Value)
	}

	for {
		tok, err := d.Token()
		if err != nil {
			return nil, err
		}
		switch tok := tok.(type) {
		case xml.StartElement:
			child, err := decodeEtreeElement(d, tok, inScope)
			if err != nil {
				return nil, err
			}
			el.AddChild(child)
		case xml.CharData:
			el.AddChild(etree.NewText(string(tok)))
		case xml.Comment:
			el.AddChild(etree.NewComment(string(tok)))
		case xml.EndElement:
			return el, nil
		}
	}
}
