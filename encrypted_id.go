package saml

import (
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/beevik/etree"
)

// decryptNameID decrypts encryptedID, a saml:EncryptedID element, with
// decrypt, which returns the root element of the plaintext, and returns the
// saml:NameID it holds. Other identifiers (BaseID, or an EncryptedID that
// does not hold a NameID) are rejected.
func decryptNameID(encryptedID *etree.Element, decrypt func(*etree.Element) (*etree.Element, error)) (*NameID, error) {
	plaintext, err := decrypt(encryptedID)
	if err != nil {
		return nil, classify(fmt.Errorf("cannot decrypt EncryptedID: %w", err), ErrDecryptionFailed)
	}
	if plaintext.Tag != "NameID" || plaintext.NamespaceURI() != "urn:oasis:names:tc:SAML:2.0:assertion" {
		return nil, classify(fmt.Errorf("EncryptedID holds a %s element, only saml:NameID is supported", plaintext.FullTag()), ErrUnsupported)
	}
	var nameID NameID
	if err := unmarshalElement(plaintext, &nameID); err != nil {
		return nil, err
	}
	return &nameID, nil
}

// resolveLogoutRequestNameID makes sure req identifies the principal with a
// NameID: if it carries an EncryptedID instead, it is decrypted with decrypt
// and NameID is set to the result. A request with both, or with neither, or
// with an empty NameID, is rejected.
func resolveLogoutRequestNameID(req *LogoutRequest, decrypt func(*etree.Element) (*etree.Element, error)) error {
	if req.NameID != nil && req.EncryptedID != nil {
		return classify(errors.New("request contains both a NameID and an EncryptedID"), ErrMalformedMessage)
	}
	if req.EncryptedID != nil {
		nameID, err := decryptNameID(req.EncryptedID, decrypt)
		if err != nil {
			return err
		}
		req.NameID = nameID
	}
	if req.NameID == nil || req.NameID.Value == "" {
		return classify(errors.New("request does not contain a NameID"), ErrMissingElement)
	}
	return nil
}

// decryptElement decrypts encryptedEl, an element with an xenc:EncryptedData
// child such as saml:EncryptedID, with the IdP's Key, and returns the root
// element of the plaintext.
//
// Key is the private key of Certificate, which the IdP metadata publishes
// as its encryption key, so it is the key a service provider encrypts to.
// Only RSA key transport is supported, so Key must be an *rsa.PrivateKey; an
// IdP that signs with Signer alone cannot decrypt.
func (idp *IdentityProvider) decryptElement(encryptedEl *etree.Element) (*etree.Element, error) {
	key, ok := idp.Key.(*rsa.PrivateKey)
	if !ok || key == nil {
		return nil, errors.New("IdentityProvider.Key is not an RSA private key")
	}
	encryptedDataEl, err := findOneChild(encryptedEl, "http://www.w3.org/2001/04/xmlenc#", "EncryptedData")
	if err != nil {
		return nil, err
	}
	plaintext, err := decryptWithKey(key, encryptedEl, encryptedDataEl)
	if err != nil {
		return nil, err
	}
	return parsePlaintext(plaintext)
}
