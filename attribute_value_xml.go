package saml

import (
	"strings"

	"github.com/beevik/etree"
)

// fillAttributeValuesXML sets AttributeValue.XML, for the attributes of
// assertion, from assertionEl, the element assertion was read from. It is
// called before encrypted attributes are added, so the attributes of each
// statement match its Attribute elements in order.
func fillAttributeValuesXML(assertionEl *etree.Element, assertion *Assertion) error {
	statementEls, err := findChildren(assertionEl, samlAssertionNamespace, "AttributeStatement")
	if err != nil {
		return err
	}
	if len(statementEls) != len(assertion.AttributeStatements) {
		return nil // the attributes cannot be matched; leave XML empty
	}
	for i, statementEl := range statementEls {
		attributeEls, err := findChildren(statementEl, samlAssertionNamespace, "Attribute")
		if err != nil {
			return err
		}
		statement := &assertion.AttributeStatements[i]
		if len(attributeEls) != len(statement.Attributes) {
			continue
		}
		for j, attributeEl := range attributeEls {
			if err := fillAttributeXML(attributeEl, &statement.Attributes[j]); err != nil {
				return err
			}
		}
	}
	return nil
}

// fillAttributeXML sets the XML of the values of attribute from
// attributeEl, the element it was read from.
func fillAttributeXML(attributeEl *etree.Element, attribute *Attribute) error {
	valueEls, err := findChildren(attributeEl, samlAssertionNamespace, "AttributeValue")
	if err != nil {
		return err
	}
	if len(valueEls) != len(attribute.Values) {
		return nil
	}
	for i, valueEl := range valueEls {
		content, err := elementContentXML(valueEl)
		if err != nil {
			return err
		}
		attribute.Values[i].XML = content
	}
	return nil
}

// elementContentXML returns the child elements of el, other than a
// saml:NameID, as XML. Each child carries the declarations of the
// namespaces in scope where it was, so that the prefixes it uses, in its
// names and in QName values such as xsi:type, resolve as they did.
func elementContentXML(el *etree.Element) (string, error) {
	var b strings.Builder
	for _, child := range el.ChildElements() {
		if child.Tag == "NameID" && child.NamespaceURI() == samlAssertionNamespace {
			continue
		}
		buf, err := elementCopyToBytes(elementWithNamespaces(child))
		if err != nil {
			return "", err
		}
		b.Write(buf)
	}
	return b.String(), nil
}
