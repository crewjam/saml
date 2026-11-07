package saml

import (
	"bytes"
	"encoding/xml"
	"strconv"
	"strings"
)

// xmlSchemaInstanceNamespace is the namespace of xsi:type and xsi:nil.
const xmlSchemaInstanceNamespace = "http://www.w3.org/2001/XMLSchema-instance"

// UnmarshalXML implements xml.Unmarshaler. It reads the attributes, the
// text and a NameID as the struct tags of AttributeValue describe, and
// keeps any other child elements in XML.
func (a *AttributeValue) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*a = AttributeValue{}
	for _, attr := range start.Attr {
		switch {
		case attr.Name.Space == xmlSchemaInstanceNamespace && attr.Name.Local == "type":
			a.Type = attr.Value
		case attr.Name.Space == xmlSchemaInstanceNamespace && attr.Name.Local == "nil":
			isNil, err := strconv.ParseBool(strings.TrimSpace(attr.Value))
			if err != nil {
				return err
			}
			a.Nil = isNil
		case attr.Name.Space == X500AttributeNamespace && attr.Name.Local == "Encoding":
			a.Encoding = attr.Value
		}
	}

	var text strings.Builder
	var content bytes.Buffer
	enc := xml.NewEncoder(&content)
	depth := 0
	for {
		tok, err := d.Token()
		if err != nil {
			return err
		}
		switch t := tok.(type) {
		case xml.StartElement:
			if depth == 0 && a.NameID == nil &&
				t.Name.Space == "urn:oasis:names:tc:SAML:2.0:assertion" && t.Name.Local == "NameID" {
				var nameID NameID
				if err := d.DecodeElement(&nameID, &t); err != nil {
					return err
				}
				a.NameID = &nameID
				continue
			}
			depth++
			if err := enc.EncodeToken(t.Copy()); err != nil {
				return err
			}
		case xml.EndElement:
			if depth == 0 {
				a.Value = text.String()
				if err := enc.Flush(); err != nil {
					return err
				}
				a.XML = content.String()
				return nil
			}
			depth--
			if err := enc.EncodeToken(t); err != nil {
				return err
			}
		case xml.CharData:
			if depth == 0 {
				text.Write(t)
			} else if err := enc.EncodeToken(t.Copy()); err != nil {
				return err
			}
		}
	}
}
