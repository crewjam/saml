package samlidp

import (
	"errors"
	"fmt"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
)

// EnableInsecureAESCBC lets the IdP encrypt to an SP with AES-CBC when the
// SP's metadata lists AES-CBC block ciphers and no AES-GCM one. Pass it to
// New.
//
// By default the IdP encrypts assertions, and the NameIDs of
// LogoutRequests, only with AES-GCM: with the strongest AES-GCM cipher the
// SP's metadata lists for its encryption key, or AES-256-GCM if it lists
// no block cipher, and it refuses to encrypt to an SP that lists only
// AES-CBC. AES-CBC has no integrity protection: an SP that decrypts before
// it checks a signature over what it decrypted can be made to reveal the
// plaintext, by an attacker who sends it modified ciphertexts and watches
// whether they decrypt.
//
// Even with this option, an SP that lists no block cipher gets AES-GCM. An
// SP that cannot decrypt AES-GCM, and does not say so, needs its metadata
// to list the AES-CBC ciphers it supports, such as
// http://www.w3.org/2001/04/xmlenc#aes128-cbc, in the EncryptionMethods of
// its encryption key. Keep the Response signed for such SPs (see
// saml.SignResponseAndAssertion), so that one that checks the signature
// first is not exposed.
//
// It also lets a saml.IdentityProvider's AssertionEncrypter or
// LogoutNameIDEncrypter, set with an IdentityProviderOption, use AES-CBC.
var EnableInsecureAESCBC Option = optionFunc(func(c *Config, _ *configOptions) { c.allowCBC = true })

// EnableInsecureRSAOAEPSHA1 lets the IdP encrypt to an SP with RSA-OAEP
// key transport that uses SHA-1, when the SP's metadata lists
// http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p, whose mask generation
// function is always MGF1 with SHA-1, and not
// http://www.w3.org/2009/xmlenc11#rsa-oaep. Pass it to New.
//
// By default the IdP encrypts the key of each encrypted assertion or NameID
// with XML Encryption 1.1 RSA-OAEP using SHA-256 for both the digest and
// MGF1, and refuses to encrypt to an SP whose metadata lists only key
// transport algorithms that need SHA-1. An SP whose metadata lists no key
// transport algorithm gets RSA-OAEP with SHA-256, even with this option:
// one that cannot decrypt it needs its metadata to list rsa-oaep-mgf1p.
// RSA PKCS#1 v1.5 key transport is never used.
//
// No attack is known on RSA-OAEP with SHA-1, whose security does not rest
// on collision resistance, the property of SHA-1 that is broken. It is off
// by default because SHA-1 is being retired everywhere (NIST is to
// disallow it after 2030), and because the SPs that cannot use SHA-256 are
// the ones least likely to support anything else this package wants.
//
// It also lets a saml.IdentityProvider's AssertionEncrypter or
// LogoutNameIDEncrypter, set with an IdentityProviderOption, use SHA-1.
var EnableInsecureRSAOAEPSHA1 Option = optionFunc(func(c *Config, _ *configOptions) { c.allowSHA1 = true })

const (
	algorithmRSAOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	algorithmRSAOAEP11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	algorithmRSA15        = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
)

// The block ciphers the IdP chooses from, in order of preference.
var (
	gcmBlockCiphers = []xmlenc.BlockCipher{xmlenc.AES256GCM, xmlenc.AES128GCM, xmlenc.AES192GCM}
	cbcBlockCiphers = []xmlenc.BlockCipher{xmlenc.AES256CBC, xmlenc.AES128CBC, xmlenc.AES192CBC}
)

// encryptionPolicy chooses and checks the algorithms the IdP encrypts
// with.
type encryptionPolicy struct {
	allowCBC, allowSHA1 bool
}

func (c *Config) encryption() encryptionPolicy {
	return encryptionPolicy{allowCBC: c.allowCBC, allowSHA1: c.allowSHA1}
}

// apply makes idp encrypt assertions and logout NameIDs only as p allows.
// An AssertionEncrypter or LogoutNameIDEncrypter set on idp is moved into
// the matching Func, which checks it each time it is used; so is what a
// Func set on idp returns.
func (p encryptionPolicy) apply(idp *saml.IdentityProvider) {
	idp.AssertionEncrypterFunc = p.encrypterFunc(idp.AssertionEncrypter, idp.AssertionEncrypterFunc)
	idp.AssertionEncrypter = nil
	idp.LogoutNameIDEncrypterFunc = p.encrypterFunc(idp.LogoutNameIDEncrypter, idp.LogoutNameIDEncrypterFunc)
	idp.LogoutNameIDEncrypter = nil
}

func (p encryptionPolicy) encrypterFunc(configured xmlenc.Encrypter, fn func([]saml.EncryptionMethod) (xmlenc.Encrypter, error)) func([]saml.EncryptionMethod) (xmlenc.Encrypter, error) {
	return func(methods []saml.EncryptionMethod) (xmlenc.Encrypter, error) {
		switch {
		case configured != nil:
			return configured, p.check(configured)
		case fn != nil:
			enc, err := fn(methods)
			if err != nil {
				return nil, err
			}
			if enc == nil {
				return nil, errors.New("samlidp: the encrypter function returned no encrypter")
			}
			return enc, p.check(enc)
		default:
			return p.choose(methods)
		}
	}
}

// choose returns the Encrypter for an SP whose metadata lists methods for
// its encryption key, or an error if p allows none of the algorithms it
// lists.
func (p encryptionPolicy) choose(methods []saml.EncryptionMethod) (xmlenc.Encrypter, error) {
	listed := make(map[string]bool, len(methods))
	for _, m := range methods {
		listed[m.Algorithm] = true
	}

	var enc xmlenc.RSA
	switch {
	case listed[algorithmRSAOAEP11] || !listed[algorithmRSAOAEPMGF1P] && !listed[algorithmRSA15]:
		enc = xmlenc.OAEP_SHA256()
	case listed[algorithmRSAOAEPMGF1P] && p.allowSHA1:
		// MGF1 is SHA-1 anyway; a SHA-1 digest is what every
		// implementation of rsa-oaep-mgf1p supports.
		enc = xmlenc.OAEP()
		enc.DigestMethod = xmlenc.SHA1
	case listed[algorithmRSAOAEPMGF1P]:
		return nil, errors.New("samlidp: the service provider's metadata lists RSA-OAEP key transport only with SHA-1 (" + algorithmRSAOAEPMGF1P + "), not " + algorithmRSAOAEP11 + "; see EnableInsecureRSAOAEPSHA1")
	default:
		return nil, errors.New("samlidp: the service provider's metadata lists only RSA PKCS#1 v1.5 key transport, which is insecure and never used")
	}

	enc.BlockCipher = nil
	for _, bc := range gcmBlockCiphers {
		if listed[bc.Algorithm()] {
			enc.BlockCipher = bc
			break
		}
	}
	if enc.BlockCipher == nil {
		var cbc xmlenc.BlockCipher
		for _, bc := range cbcBlockCiphers {
			if listed[bc.Algorithm()] {
				cbc = bc
				break
			}
		}
		switch {
		case cbc == nil:
			enc.BlockCipher = xmlenc.AES256GCM
		case p.allowCBC:
			enc.BlockCipher = cbc
		default:
			return nil, errors.New("samlidp: the service provider's metadata lists only AES-CBC block ciphers, which have no integrity protection; see EnableInsecureAESCBC")
		}
	}
	return enc, nil
}

// check returns an error if enc uses an algorithm p does not allow. It can
// only check an xmlenc.RSA: an Encrypter of another type is used as it is.
func (p encryptionPolicy) check(enc xmlenc.Encrypter) error {
	var rsa xmlenc.RSA
	switch e := enc.(type) {
	case xmlenc.RSA:
		rsa = e
	case *xmlenc.RSA:
		if e == nil {
			return errors.New("samlidp: the encrypter is a nil *xmlenc.RSA")
		}
		rsa = *e
	default:
		return nil
	}
	switch rsa.Algorithm() {
	case algorithmRSA15:
		return errors.New("samlidp: the encrypter uses RSA PKCS#1 v1.5 key transport, which is insecure and never used")
	case algorithmRSAOAEPMGF1P:
		if !p.allowSHA1 {
			return errors.New("samlidp: the encrypter uses " + algorithmRSAOAEPMGF1P + ", whose MGF1 uses SHA-1; see EnableInsecureRSAOAEPSHA1")
		}
	case algorithmRSAOAEP11:
		if rsa.DigestMethod != nil && rsa.DigestMethod.Algorithm() == xmlenc.SHA1.Algorithm() && !p.allowSHA1 {
			return errors.New("samlidp: the encrypter uses RSA-OAEP with SHA-1; see EnableInsecureRSAOAEPSHA1")
		}
	}
	if rsa.BlockCipher != nil && !p.allowCBC {
		for _, bc := range cbcBlockCiphers {
			if rsa.BlockCipher.Algorithm() == bc.Algorithm() {
				return fmt.Errorf("samlidp: the encrypter uses %s, which has no integrity protection; see EnableInsecureAESCBC", bc.Algorithm())
			}
		}
	}
	return nil
}

// checkConfigured returns an error if an encrypter set on idp, before
// apply, uses an algorithm p does not allow.
func (p encryptionPolicy) checkConfigured(idp *saml.IdentityProvider) error {
	for _, enc := range []xmlenc.Encrypter{idp.AssertionEncrypter, idp.LogoutNameIDEncrypter} {
		if enc != nil {
			if err := p.check(enc); err != nil {
				return err
			}
		}
	}
	return nil
}
