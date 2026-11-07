package saml

import (
	"errors"
	"fmt"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
)

// sha1Algorithms are the XML Signature algorithm identifiers (used as
// SignatureMethod and DigestMethod Algorithm values, and as the SigAlg of the
// HTTP-Redirect and HTTP-POST-SimpleSign bindings) that are based on SHA-1.
var sha1Algorithms = map[string]bool{
	dsig.RSASHA1SignatureMethod:                   true,
	dsig.ECDSASHA1SignatureMethod:                 true,
	"http://www.w3.org/2000/09/xmldsig#dsa-sha1":  true,
	"http://www.w3.org/2000/09/xmldsig#hmac-sha1": true,
	"http://www.w3.org/2000/09/xmldsig#sha1":      true,
}

// errSHA1Algorithm is returned when a message is signed with a SHA-1 based
// algorithm and SHA-1 is rejected (see ServiceProvider.RejectSHA1Signatures
// and IdentityProvider.RejectSHA1Signatures). It matches ErrUnsupported.
var errSHA1Algorithm = classify(errors.New("SHA-1 based signature algorithms are not accepted"), ErrUnsupported)

// checkSigAlgNotSHA1 returns an error if reject is set and sigAlg, the SigAlg
// of an HTTP-Redirect or HTTP-POST-SimpleSign message, is based on SHA-1.
func checkSigAlgNotSHA1(reject bool, sigAlg string) error {
	if reject && sha1Algorithms[sigAlg] {
		return fmt.Errorf("signature algorithm %q: %w", sigAlg, errSHA1Algorithm)
	}
	return nil
}

// checkXMLSignatureNotSHA1 returns an error if reject is set and the XML
// signature sigEl (a ds:Signature element) uses a SHA-1 based
// SignatureMethod or DigestMethod. Every SignatureMethod and DigestMethod
// element in sigEl is checked, wherever it is, so that no arrangement of the
// elements can hide one from the check.
func checkXMLSignatureNotSHA1(reject bool, sigEl *etree.Element) error {
	if !reject || sigEl == nil {
		return nil
	}
	for _, path := range []string{".//SignatureMethod", ".//DigestMethod"} {
		for _, el := range sigEl.FindElements(path) {
			for _, attr := range el.Attr {
				if attr.Key == "Algorithm" && sha1Algorithms[attr.Value] {
					return fmt.Errorf("%s %q: %w", el.Tag, attr.Value, errSHA1Algorithm)
				}
			}
		}
	}
	return nil
}

// checkEnvelopedSignatureNotSHA1 returns an error if reject is set and the
// enveloped XML signature of el, its ds:Signature child, uses a SHA-1 based
// algorithm (see checkXMLSignatureNotSHA1). An element without a signature
// passes.
func checkEnvelopedSignatureNotSHA1(reject bool, el *etree.Element) error {
	if !reject {
		return nil
	}
	sigEl, err := findChild(el, dsig.Namespace, "Signature")
	if err != nil {
		return err
	}
	return checkXMLSignatureNotSHA1(reject, sigEl)
}
