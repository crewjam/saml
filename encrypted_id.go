package saml

import (
	"crypto/rsa"
	"crypto/x509"
	"errors"
	"fmt"

	"github.com/beevik/etree"

	"github.com/crewjam/saml/xmlenc"
)

const samlAssertionNamespace = "urn:oasis:names:tc:SAML:2.0:assertion"

// decryptIdentifier decrypts encryptedID, a saml:EncryptedID element, with
// decrypt, which returns the root element of the plaintext. It returns the
// saml:NameID it holds, or else the saml:BaseID it holds. Anything else is
// rejected.
func decryptIdentifier(encryptedID *etree.Element, decrypt func(*etree.Element) (*etree.Element, error)) (*NameID, *etree.Element, error) {
	plaintext, err := decrypt(encryptedID)
	if err != nil {
		return nil, nil, classify(fmt.Errorf("cannot decrypt EncryptedID: %w", err), ErrDecryptionFailed)
	}
	if plaintext.NamespaceURI() == samlAssertionNamespace {
		switch plaintext.Tag {
		case "NameID":
			var nameID NameID
			if err := unmarshalElement(plaintext, &nameID); err != nil {
				return nil, nil, err
			}
			return &nameID, nil, nil
		case "BaseID":
			return nil, plaintext, nil
		}
	}
	return nil, nil, classify(fmt.Errorf("EncryptedID holds a %s element, only saml:NameID and saml:BaseID are supported", plaintext.FullTag()), ErrUnsupported)
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
		nameID, baseID, err := decryptIdentifier(req.EncryptedID, decrypt)
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
// saml:NameID or saml:BaseID element, encrypted to cert with encrypter, or
// with RSA-OAEP-MGF1P, SHA-1 and AES-128-CBC if encrypter is nil. identifier
// is not modified.
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

	if encrypter == nil {
		rsaEncrypter := xmlenc.OAEP()
		rsaEncrypter.BlockCipher = xmlenc.AES128CBC
		rsaEncrypter.DigestMethod = &xmlenc.SHA1
		encrypter = rsaEncrypter
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

// namedDecryptionKey is a decryption key and the name of the field it comes
// from, for error messages.
type namedDecryptionKey struct {
	name string
	key  interface{}
}

// decryptWithKeys decrypts encryptedEl, an element with an
// xenc:EncryptedData child such as saml:EncryptedID or
// saml:EncryptedAssertion, with the first of keys that can, and returns the
// root element of the plaintext.
func decryptWithKeys(encryptedEl *etree.Element, keys []namedDecryptionKey) (*etree.Element, error) {
	encryptedDataEl, err := findOneChild(encryptedEl, "http://www.w3.org/2001/04/xmlenc#", "EncryptedData")
	if err != nil {
		return nil, err
	}
	if len(keys) == 0 {
		return nil, errors.New("no decryption key")
	}

	plaintext, err := decryptWithKey(keys[0].key, encryptedEl, encryptedDataEl)
	if err != nil && len(keys) > 1 {
		// Key transport is RSA-OAEP only, which fails the same way for every
		// wrong key, so trying several keys reveals no more than trying one.
		errs := []error{fmt.Errorf("%s: %w", keys[0].name, err)}
		for _, k := range keys[1:] {
			var keyErr error
			if plaintext, keyErr = decryptWithKey(k.key, encryptedEl, encryptedDataEl); keyErr == nil {
				err = nil
				break
			}
			errs = append(errs, fmt.Errorf("%s: %w", k.name, keyErr))
		}
		if err != nil {
			err = fmt.Errorf("no decryption key could decrypt it: %w", errors.Join(errs...))
		}
	}
	if err != nil {
		return nil, err
	}
	return parsePlaintext(plaintext)
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
	return decryptWithKeys(encryptedEl, keys)
}
