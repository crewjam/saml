package xmlenc

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"encoding/base64"
	"testing"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	is "gotest.tools/v3/assert/cmp"
)

// The XML Encryption 1.1 RSA-OAEP key transport round trips through Encrypt
// and Decrypt, and states the mask generation function it used.
func TestOAEP11RoundTrip(t *testing.T) {
	key, cert := newKeyAndCert(t)
	for name, tc := range map[string]struct {
		enc    RSA
		mgfURI string
	}{
		"OAEP_SHA256":     {OAEP_SHA256(), "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
		"OAEP_SHA384":     {OAEP_SHA384(), "http://www.w3.org/2009/xmlenc11#mgf1sha384"},
		"OAEP_SHA512":     {OAEP_SHA512(), "http://www.w3.org/2009/xmlenc11#mgf1sha512"},
		"OAEP_SHA256/GCM": {func() RSA { e := OAEP_SHA256(); e.BlockCipher = AES256GCM; return e }(), "http://www.w3.org/2009/xmlenc11#mgf1sha256"},
		"SHA1 digest":     {func() RSA { e := OAEP_SHA256(); e.DigestMethod = SHA1; return e }(), "http://www.w3.org/2009/xmlenc11#mgf1sha1"},
	} {
		t.Run(name, func(t *testing.T) {
			el, err := tc.enc.Encrypt(cert, []byte("hello"), nil)
			assert.NilError(t, err)

			em := el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod")
			assert.Assert(t, em != nil)
			assert.Check(t, is.Equal("http://www.w3.org/2009/xmlenc11#rsa-oaep", em.SelectAttrValue("Algorithm", "")))
			mgf := em.FindElement("./MGF")
			assert.Assert(t, mgf != nil)
			assert.Check(t, is.Equal(tc.mgfURI, mgf.SelectAttrValue("Algorithm", "")))

			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
		})
	}
}

// oaepDocument builds an EncryptedData element whose AES-256-CBC key is wrapped
// with RSA-OAEP using the given options, the way another implementation would.
// digestURI, mgfURI and the label are only written to the document when not
// empty.
func oaepDocument(t *testing.T, pub *rsa.PublicKey, algorithm string, opts *rsa.OAEPOptions, digestURI, mgfURI string) *etree.Element {
	t.Helper()
	sessionKey := make([]byte, 32)
	_, err := rand.Read(sessionKey)
	assert.NilError(t, err)
	wrapped, err := rsaEncryptOAEP(rand.Reader, pub, sessionKey, opts)
	assert.NilError(t, err)

	el, err := AES256CBC.Encrypt(sessionKey, []byte("hello"), nil)
	assert.NilError(t, err)

	ek := etree.NewElement("xenc:EncryptedKey")
	em := ek.CreateElement("xenc:EncryptionMethod")
	em.CreateAttr("Algorithm", algorithm)
	if digestURI != "" {
		em.CreateElement("ds:DigestMethod").CreateAttr("Algorithm", digestURI)
	}
	if mgfURI != "" {
		em.CreateElement("xenc11:MGF").CreateAttr("Algorithm", mgfURI)
	}
	if len(opts.Label) > 0 {
		em.CreateElement("xenc:OAEPparams").SetText(base64.StdEncoding.EncodeToString(opts.Label))
	}
	ek.CreateElement("xenc:CipherData").CreateElement("xenc:CipherValue").
		SetText(base64.StdEncoding.EncodeToString(wrapped))
	el.InsertChildAt(el.FindElement("./CipherData").Index(), etree.NewElement("ds:KeyInfo"))
	el.FindElement("./KeyInfo").AddChild(ek)
	return el
}

// Documents produced by other implementations decrypt, including the default
// MGF1-SHA-1 when no MGF element is present and an OAEP label.
func TestOAEPDecryptsSpecShapedDocuments(t *testing.T) {
	key, _ := newKeyAndCert(t)
	for name, tc := range map[string]struct {
		algorithm string
		opts      rsa.OAEPOptions
		digestURI string
		mgfURI    string
	}{
		"rsa-oaep sha256 default mgf": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1},
			digestURI: SHA256.Algorithm(),
		},
		"rsa-oaep sha256 explicit mgf1sha1": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1},
			digestURI: SHA256.Algorithm(),
			mgfURI:    "http://www.w3.org/2009/xmlenc11#mgf1sha1",
		},
		"rsa-oaep sha512 mgf1sha384": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA512, MGFHash: crypto.SHA384},
			digestURI: SHA512.Algorithm(),
			mgfURI:    "http://www.w3.org/2009/xmlenc11#mgf1sha384",
		},
		"rsa-oaep sha384 mgf1sha384": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA384, MGFHash: crypto.SHA384},
			digestURI: "http://www.w3.org/2001/04/xmldsig-more#sha384",
			mgfURI:    "http://www.w3.org/2009/xmlenc11#mgf1sha384",
		},
		"rsa-oaep-mgf1p sha384": {
			algorithm: algorithmRSAOAEPMGF1P,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA384, MGFHash: crypto.SHA1},
			digestURI: "http://www.w3.org/2001/04/xmldsig-more#sha384",
		},
		"rsa-oaep default digest and mgf": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA1, MGFHash: crypto.SHA1},
		},
		"rsa-oaep with label": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256, Label: []byte("label")},
			digestURI: SHA256.Algorithm(),
			mgfURI:    "http://www.w3.org/2009/xmlenc11#mgf1sha256",
		},
		"rsa-oaep-mgf1p sha256": {
			algorithm: algorithmRSAOAEPMGF1P,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1},
			digestURI: SHA256.Algorithm(),
		},
		// Earlier releases of this package used the digest for MGF1 without
		// saying so. Those documents still decrypt.
		"legacy rsa-oaep sha256": {
			algorithm: algorithmRSAOAEP11,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256},
			digestURI: SHA256.Algorithm(),
		},
		"legacy rsa-oaep-mgf1p sha512": {
			algorithm: algorithmRSAOAEPMGF1P,
			opts:      rsa.OAEPOptions{Hash: crypto.SHA512, MGFHash: crypto.SHA512},
			digestURI: SHA512.Algorithm(),
		},
	} {
		t.Run(name, func(t *testing.T) {
			el := oaepDocument(t, &key.PublicKey, tc.algorithm, &tc.opts, tc.digestURI, tc.mgfURI)
			plaintext, err := Decrypt(key, el)
			assert.NilError(t, err)
			assert.Check(t, is.DeepEqual([]byte("hello"), plaintext))
		})
	}
}

// A stated MGF is used as given: the legacy fallback only applies when the
// document names none.
func TestOAEPExplicitMGFIsNotRetried(t *testing.T) {
	key, _ := newKeyAndCert(t)
	el := oaepDocument(t, &key.PublicKey, algorithmRSAOAEP11,
		&rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA256},
		SHA256.Algorithm(), "http://www.w3.org/2009/xmlenc11#mgf1sha1")
	_, err := Decrypt(key, el)
	assert.Check(t, is.ErrorIs(err, rsa.ErrDecryption))
}

func TestOAEPRejectsBadMGF(t *testing.T) {
	key, _ := newKeyAndCert(t)
	t.Run("unknown MGF", func(t *testing.T) {
		el := oaepDocument(t, &key.PublicKey, algorithmRSAOAEP11,
			&rsa.OAEPOptions{Hash: crypto.SHA256}, SHA256.Algorithm(), "urn:example:mgf")
		_, err := Decrypt(key, el)
		assert.Check(t, is.Error(err, ErrAlgorithmNotImplemented("urn:example:mgf").Error()))
	})
	t.Run("MGF with rsa-oaep-mgf1p", func(t *testing.T) {
		el := oaepDocument(t, &key.PublicKey, algorithmRSAOAEPMGF1P,
			&rsa.OAEPOptions{Hash: crypto.SHA256}, SHA256.Algorithm(), "http://www.w3.org/2009/xmlenc11#mgf1sha256")
		_, err := Decrypt(key, el)
		assert.Check(t, is.ErrorContains(err, "algorithm is not implemented"))
	})
	t.Run("bad OAEPparams", func(t *testing.T) {
		el := oaepDocument(t, &key.PublicKey, algorithmRSAOAEP11,
			&rsa.OAEPOptions{Hash: crypto.SHA256, Label: []byte("x")}, SHA256.Algorithm(), "")
		el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/OAEPparams").SetText("!!")
		_, err := Decrypt(key, el)
		assert.Check(t, is.ErrorContains(err, "cannot decode OAEPparams"))
	})
}

// RSA-OAEP-MGF1P always uses MGF1 with SHA-1, whatever the digest, so other
// implementations can unwrap the key.
func TestOAEPMGF1PUsesSHA1MGF(t *testing.T) {
	key, cert := newKeyAndCert(t)
	e := OAEP()
	e.DigestMethod = SHA256
	el, err := e.Encrypt(cert, []byte("hello"), nil)
	assert.NilError(t, err)
	assert.Check(t, el.FindElement("./KeyInfo/EncryptedKey/EncryptionMethod/MGF") == nil)

	wrapped, err := getCiphertext(el.FindElement("./KeyInfo/EncryptedKey"))
	assert.NilError(t, err)
	_, err = key.Decrypt(rand.Reader, wrapped, &rsa.OAEPOptions{Hash: crypto.SHA256, MGFHash: crypto.SHA1})
	assert.NilError(t, err)
}
