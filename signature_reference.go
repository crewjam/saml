package saml

import (
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// checkSignatureReference checks that the enveloped ds:Signature of el (its
// direct child) follows the reference profile of saml-core-2.0-os §5.4.2
// and saml-metadata-2.0-os §3.1: "Signatures MUST contain a single
// <ds:Reference> containing a same-document reference to the ID attribute
// value of the root element", that is, a URI of "#" followed by el's ID.
//
// goxmldsig does not enforce this: it accepts URI="" (the whole document),
// a URI whose first character is not "#", and several References, of which
// it digests only the first that matches el. Every path that verifies an
// enveloped signature calls this once goxmldsig has accepted it, so that
// signatures goxmldsig rejects keep its error. Violations match
// ErrInvalidSignature, and a signed element without an ID also matches
// ErrMissingElement.
func checkSignatureReference(el *etree.Element) error {
	sigEl, err := findChild(el, dsig.Namespace, "Signature")
	if err != nil {
		return err
	}
	if sigEl == nil {
		return errSignatureElementNotPresent
	}
	var refs []*etree.Element
	if signedInfo, err := findChild(sigEl, dsig.Namespace, "SignedInfo"); err != nil {
		return err
	} else if signedInfo != nil {
		if refs, err = findChildren(signedInfo, dsig.Namespace, "Reference"); err != nil {
			return err
		}
	}
	if len(refs) != 1 {
		return classify(fmt.Errorf("signature must contain exactly one Reference, not %d", len(refs)), ErrInvalidSignature)
	}
	id := el.SelectAttrValue("ID", "")
	if id == "" {
		return classify(fmt.Errorf("signed %s has no ID for its signature to reference", el.Tag), ErrInvalidSignature, ErrMissingElement)
	}
	// Look at every attribute named URI, whatever its prefix, so that a
	// prefixed one cannot stand in for (or next to) the real one.
	var uris []string
	unprefixed := true
	for _, attr := range refs[0].Attr {
		if attr.Key == "URI" {
			uris = append(uris, attr.Value)
			unprefixed = unprefixed && attr.Space == ""
		}
	}
	if len(uris) != 1 || !unprefixed || uris[0] != "#"+id {
		return classify(fmt.Errorf("signature Reference URI must be %q, not %q", "#"+id, uris), ErrInvalidSignature)
	}
	return nil
}
