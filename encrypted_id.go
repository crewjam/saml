package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"os"
	"regexp"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/xmlenc"
)

const samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"

// decryptNameID decrypts encryptedID, a saml:EncryptedID element, with
// decrypt, which returns the root element of the plaintext, and returns the
// saml:NameID it holds. Other identifiers (BaseID, or an EncryptedID that
// does not hold a NameID) are rejected.
func decryptNameID(encryptedID *etree.Element, decrypt func(*etree.Element) (*etree.Element, error)) (*NameID, error) {
	nameID, _, err := decryptIdentifier(encryptedID, decrypt, false)
	return nameID, err
}

// decryptIdentifier decrypts encryptedID, a saml:EncryptedID element, with
// decrypt, which returns the root element of the plaintext. It returns the
// saml:NameID it holds or, if allowBaseID is true, the saml:BaseID it holds.
// Anything else is rejected.
func decryptIdentifier(encryptedID *etree.Element, decrypt func(*etree.Element) (*etree.Element, error), allowBaseID bool) (*NameID, *etree.Element, error) {
	plaintext, err := decrypt(encryptedID)
	if err != nil {
		return nil, nil, classify(fmt.Errorf("cannot decrypt EncryptedID: %w", err), ErrDecryptionFailed)
	}
	if plaintext.NamespaceURI() == samlAssertionNamespace {
		switch {
		case plaintext.Tag == "NameID":
			var nameID NameID
			if err := unmarshalElement(plaintext, &nameID); err != nil {
				return nil, nil, err
			}
			return &nameID, nil, nil
		case plaintext.Tag == "BaseID" && allowBaseID:
			return nil, plaintext, nil
		}
	}
	supported := "saml:NameID"
	if allowBaseID {
		supported = "saml:NameID and saml:BaseID are"
	} else {
		supported += " is"
	}
	return nil, nil, classify(fmt.Errorf("EncryptedID holds a %s element, only %s supported", plaintext.FullTag(), supported), ErrUnsupported)
}

// resolveLogoutRequestNameID makes sure req identifies the principal with
// exactly one of BaseID, NameID and EncryptedID, as saml-core-2.0-os §3.7.1
// requires. An EncryptedID is decrypted with decrypt, and NameID or BaseID
// is set to what it holds. A request identified by a BaseID is accepted only
// if acceptBaseID is true; otherwise the principal must be a non-empty
// NameID.
func resolveLogoutRequestNameID(req *LogoutRequest, decrypt func(*etree.Element) (*etree.Element, error), acceptBaseID bool) error {
	identifiers := 0
	for _, set := range []bool{req.BaseID != nil, req.NameID != nil, req.EncryptedID != nil} {
		if set {
			identifiers++
		}
	}
	if identifiers > 1 {
		return classify(errors.New("request contains more than one of BaseID, NameID and EncryptedID"), ErrMalformedMessage)
	}
	if req.EncryptedID != nil {
		nameID, baseID, err := decryptIdentifier(req.EncryptedID, decrypt, true)
		if err != nil {
			return err
		}
		req.NameID, req.BaseID = nameID, baseID
	}
	if req.BaseID != nil {
		if !acceptBaseID {
			return classify(errors.New("request identifies the principal with a BaseID, which is not accepted"), ErrUnsupported)
		}
		return nil
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return classify(errors.New("request does not contain a NameID"), ErrMissingElement)
	}
	return nil
}

// encryptIdentifier returns a saml:EncryptedID holding identifier, a
// saml:NameID or saml:BaseID element, encrypted to cert with encrypter.
// identifier is not modified.
func encryptIdentifier(identifier *etree.Element, cert *x509.Certificate, encrypter xmlenc.Encrypter) (*etree.Element, error) {
	// The plaintext is parsed on its own, so it must declare the namespace
	// of its prefix.
	identifier = identifier.Copy()
	if identifier.Space != "" && identifier.SelectAttr("xmlns:"+identifier.Space) == nil {
		identifier.CreateAttr("xmlns:"+identifier.Space, samlAssertionNamespace)
	}
	doc := etree.NewDocument()
	doc.SetRoot(identifier)
	plaintext, err := doc.WriteToBytes()
	if err != nil {
		return nil, err
	}

	encryptedData, err := encrypter.Encrypt(cert, plaintext, nil)
	if err != nil {
		return nil, err
	}
	encryptedData.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")

	encryptedID := etree.NewElement("saml:EncryptedID")
	encryptedID.AddChild(encryptedData)
	return encryptedID, nil
}

// identifierBlockCiphers are the block ciphers identifierEncrypter may
// choose, in order of preference. AES-GCM comes first: CBC has no integrity
// check, so a sender of modified ciphertexts can learn about the plaintext
// from whether it decrypts to valid XML.
var identifierBlockCiphers = []xmlenc.BlockCipher{
	xmlenc.AES256GCM, xmlenc.AES128GCM, xmlenc.AES192GCM,
	xmlenc.AES256CBC, xmlenc.AES128CBC, xmlenc.AES192CBC,
}

// identifierEncrypter returns the Encrypter for an EncryptedID: configured,
// if it is set, and otherwise RSA-OAEP-MGF1P (with a SHA-1 digest, which all
// implementations support) and a block cipher chosen from methods, the
// EncryptionMethods the recipient's metadata lists for its encryption key.
// The block cipher is the first of identifierBlockCiphers that methods
// lists, or AES-256-GCM if methods lists none of them.
func identifierEncrypter(configured xmlenc.Encrypter, methods []EncryptionMethod) xmlenc.Encrypter {
	if configured != nil {
		return configured
	}
	encrypter := xmlenc.OAEP()
	encrypter.DigestMethod = xmlenc.SHA1
	encrypter.BlockCipher = xmlenc.AES256GCM
	listed := make(map[string]bool, len(methods))
	for _, method := range methods {
		listed[method.Algorithm] = true
	}
	for _, blockCipher := range identifierBlockCiphers {
		if listed[blockCipher.Algorithm()] {
			encrypter.BlockCipher = blockCipher
			break
		}
	}
	return encrypter
}

// encryptionKey returns the certificate to encrypt to from the
// KeyDescriptors of an entity's metadata, and the EncryptionMethods listed
// with it: the first certificate whose KeyDescriptor has use="encryption",
// or else the first one whose KeyDescriptor has no use. It returns
// os.ErrNotExist if there is none.
func encryptionKey(keyDescriptors []KeyDescriptor) (*x509.Certificate, []EncryptionMethod, error) {
	for _, use := range []string{"encryption", ""} {
		for _, keyDescriptor := range keyDescriptors {
			if keyDescriptor.Use != use {
				continue
			}
			for _, certificate := range keyDescriptor.KeyInfo.X509Data.X509Certificates {
				certStr := whitespaceRegexp.ReplaceAllString(certificate.Data, "")
				if certStr == "" {
					continue
				}
				certBytes, err := base64.StdEncoding.DecodeString(certStr)
				if err != nil {
					return nil, nil, classify(fmt.Errorf("cannot decode certificate base64: %w", err), ErrInvalidCertificate)
				}
				cert, err := x509.ParseCertificate(certBytes)
				if err != nil {
					return nil, nil, classify(fmt.Errorf("cannot parse certificate: %w", err), ErrInvalidCertificate)
				}
				return cert, keyDescriptor.EncryptionMethods, nil
			}
		}
	}
	return nil, nil, os.ErrNotExist
}

var whitespaceRegexp = regexp.MustCompile(`\s+`)

// namedDecryptionKey is a decryption key and the name of the field it comes
// from, for error messages.
type namedDecryptionKey struct {
	name string
	key  interface{}
}

// maxEncryptedKeyCandidates is the most xenc:EncryptedKey elements
// decryptWithKeys tries. Encrypted elements may be decrypted before any
// signature over them is checked, and each candidate costs a private-key
// operation for every decryption key, so the number tried is bounded. The
// ones whose Recipient matches are tried first, so a legitimate
// multi-recipient element still decrypts.
const maxEncryptedKeyCandidates = 4

// decryptWithKeys decrypts encryptedEl, an element with an
// xenc:EncryptedData child such as saml:EncryptedID or
// saml:EncryptedAssertion, with the first of keys that can, and returns the
// root element of the plaintext. recipient is the entity ID of this party.
//
// The content key may be wrapped for several recipients, in several
// xenc:EncryptedKey elements beside the EncryptedData or inside its KeyInfo
// (saml-core errata E43, §6.3: "It is RECOMMENDED that implementations simply
// use the first key they understand and ignore any additional keys"). Those
// whose Recipient is recipient are tried first, then the others in document
// order, each with every one of keys. At most maxEncryptedKeyCandidates
// EncryptedKeys are tried.
func decryptWithKeys(encryptedEl *etree.Element, keys []namedDecryptionKey, recipient string) (*etree.Element, error) {
	encryptedDataEl, err := findOneChild(encryptedEl, "http://www.w3.org/2001/04/xmlenc#", "EncryptedData")
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no decryption key")
	}

	encryptedKeyEls := encryptedKeyCandidates(encryptedEl, encryptedDataEl, recipient)
	if len(encryptedKeyEls) > maxEncryptedKeyCandidates {
		// Each candidate costs one private-key operation per key, and the
		// element may come from an unsigned Response, so an attacker could
		// otherwise make one request cost seconds of CPU.
		encryptedKeyEls = encryptedKeyEls[:maxEncryptedKeyCandidates]
	}
	if len(encryptedKeyEls) == 0 {
		// No EncryptedKey: the keys are used on the EncryptedData directly.
		encryptedKeyEls = []*etree.Element{nil}
	}

	// Only the failures of the first EncryptedKey tried are reported, so
	// that the error says no more than it did when only that one was tried.
	// Key transport is RSA-OAEP only, which fails the same way for every
	// wrong key, so trying several keys reveals no more than trying one.
	var errs []error
	for i, encryptedKeyEl := range encryptedKeyEls {
		for _, k := range keys {
			plaintext, keyErr := decryptWithKey(k.key, encryptedEl, encryptedKeyEl, encryptedDataEl)
			if keyErr == nil {
				return parsePlaintext(plaintext)
			}
			if i == 0 {
				errs = append(errs, fmt.Errorf("%s: %w", k.name, keyErr))
			}
		}
	}
	if len(keys) == 1 {
		return nil, errors.Unwrap(errs[0])
	}
	return nil, fmt.Errorf("no decryption key could decrypt it: %w", errors.Join(errs...))
}

// encryptedKeyCandidates returns the xenc:EncryptedKey elements that may
// hold the content key of encryptedDataEl: those beside it in encryptedEl
// and those in its KeyInfo, the ones whose Recipient is recipient first and
// otherwise in document order.
func encryptedKeyCandidates(encryptedEl, encryptedDataEl *etree.Element, recipient string) []*etree.Element {
	all := append(encryptedEl.FindElements("./EncryptedKey"), encryptedDataEl.FindElements("./KeyInfo/EncryptedKey")...)
	matching := make([]*etree.Element, 0, len(all))
	others := make([]*etree.Element, 0, len(all))
	for _, el := range all {
		if recipient != "" && el.SelectAttrValue("Recipient", "") == recipient {
			matching = append(matching, el)
		} else {
			others = append(others, el)
		}
	}
	return append(matching, others...)
}

// decryptElement decrypts encryptedEl, an element with an xenc:EncryptedData
// child such as saml:EncryptedID, with the IdP's Key, if it is an
// *rsa.PrivateKey, then with each of DecryptionKeys, and returns the root
// element of the plaintext.
func (idp *IdentityProvider) decryptElement(encryptedEl *etree.Element) (*etree.Element, error) {
	keys := make([]namedDecryptionKey, 0, 1+len(idp.DecryptionKeys))
	if key, ok := idp.Key.(*rsa.PrivateKey); ok && key != nil {
		keys = append(keys, namedDecryptionKey{"Key", key})
	}
	for i, key := range idp.DecryptionKeys {
		if key != nil {
			keys = append(keys, namedDecryptionKey{fmt.Sprintf("DecryptionKeys[%d]", i), key})
		}
	}
	if len(keys) == 0 {
		return nil, errors.New("the IdentityProvider has no decryption key: Key is not an *rsa.PrivateKey and DecryptionKeys is empty")
	}
	return decryptWithKeys(encryptedEl, keys, idp.MetadataURL.String())
}
