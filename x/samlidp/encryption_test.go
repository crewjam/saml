package samlidp_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/xmlenc"
)

const (
	rsaOAEPMGF1P = "http://www.w3.org/2001/04/xmlenc#rsa-oaep-mgf1p"
	rsaOAEP11    = "http://www.w3.org/2009/xmlenc11#rsa-oaep"
	rsa15        = "http://www.w3.org/2001/04/xmlenc#rsa-1_5"
)

// encryptTo makes a Response for an SP whose metadata lists methods for its
// encryption key, and returns the key transport, its digest and the block
// cipher of the encrypted assertion, or the error of Response.
func encryptTo(t *testing.T, methods []string, idpOpts ...samlidp.Option) (keyTransport, digest, blockCipher string, err error) {
	t.Helper()
	keys(t)
	p := newPair(t, nil, []samlsp.Option{samlsp.WithEncryptionKey(spKey, spCert)})
	md := p.sp.Metadata(context.Background())
	for i := range md.SPSSODescriptors {
		for j := range md.SPSSODescriptors[i].KeyDescriptors {
			kd := &md.SPSSODescriptors[i].KeyDescriptors[j]
			kd.EncryptionMethods = nil
			for _, m := range methods {
				kd.EncryptionMethods = append(kd.EncryptionMethods, saml.EncryptionMethod{Algorithm: m})
			}
		}
	}
	p.idp, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(md),
		append([]samlidp.Option{samlidp.WithSigningKey(idpKey, idpCert)}, idpOpts...)...)
	if err != nil {
		t.Fatal(err)
	}
	_, root, _, err := p.tryRespond(t, testSubject)
	if root == nil {
		return "", "", "", err
	}
	if err != nil {
		t.Fatalf("the SP refused the Response: %v", errors.Unwrap(err))
	}
	data := root.FindElement("./EncryptedAssertion/EncryptedData")
	if data == nil {
		t.Fatal("the assertion is not encrypted")
	}
	key := data.FindElement(".//EncryptedKey/EncryptionMethod")
	if key == nil {
		t.Fatal("no EncryptedKey")
	}
	if dm := key.FindElement("./DigestMethod"); dm != nil {
		digest = dm.SelectAttrValue("Algorithm", "")
	}
	return key.SelectAttrValue("Algorithm", ""), digest,
		data.FindElement("./EncryptionMethod").SelectAttrValue("Algorithm", ""), nil
}

func TestEncryptionPolicy(t *testing.T) {
	gcm256, gcm128 := xmlenc.AES256GCM.Algorithm(), xmlenc.AES128GCM.Algorithm()
	cbc128 := xmlenc.AES128CBC.Algorithm()
	sha1, sha256 := xmlenc.SHA1.Algorithm(), xmlenc.SHA256.Algorithm()
	cbc := samlidp.EnableInsecureAESCBC
	oaepSHA1 := samlidp.EnableInsecureRSAOAEPSHA1
	for _, tc := range []struct {
		name                     string
		methods                  []string
		opts                     []samlidp.Option
		keyTransport, digest, bc string
		refused                  string
	}{
		{name: "none listed", keyTransport: rsaOAEP11, digest: sha256, bc: gcm256},
		{name: "none listed, both enabled", opts: []samlidp.Option{cbc, oaepSHA1}, keyTransport: rsaOAEP11, digest: sha256, bc: gcm256},
		{name: "GCM preferred", methods: []string{cbc128, gcm128}, keyTransport: rsaOAEP11, digest: sha256, bc: gcm128},
		{name: "only CBC", methods: []string{cbc128}, refused: "EnableInsecureAESCBC"},
		{name: "only CBC, enabled", methods: []string{cbc128}, opts: []samlidp.Option{cbc}, keyTransport: rsaOAEP11, digest: sha256, bc: cbc128},
		{name: "both key transports", methods: []string{rsaOAEPMGF1P, rsaOAEP11}, keyTransport: rsaOAEP11, digest: sha256, bc: gcm256},
		{name: "only mgf1p", methods: []string{rsaOAEPMGF1P}, refused: "EnableInsecureRSAOAEPSHA1"},
		{name: "only mgf1p, enabled", methods: []string{rsaOAEPMGF1P}, opts: []samlidp.Option{oaepSHA1}, keyTransport: rsaOAEPMGF1P, digest: sha1, bc: gcm256},
		{name: "only PKCS#1 v1.5", methods: []string{rsa15}, opts: []samlidp.Option{cbc, oaepSHA1}, refused: "PKCS#1 v1.5"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			keyTransport, digest, bc, err := encryptTo(t, tc.methods, tc.opts...)
			if tc.refused != "" {
				if err == nil || !strings.Contains(err.Error(), tc.refused) {
					t.Fatalf("got %v, want an error naming %s", err, tc.refused)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if keyTransport != tc.keyTransport || digest != tc.digest || bc != tc.bc {
				t.Errorf("got %s/%s/%s, want %s/%s/%s", keyTransport, digest, bc, tc.keyTransport, tc.digest, tc.bc)
			}
		})
	}
}

// An AssertionEncrypter set with an IdentityProviderOption is checked too:
// New refuses one passed to it, and Response one passed to it.
func TestEncryptionPolicyConfiguredEncrypter(t *testing.T) {
	keys(t)
	cbcEnc := xmlenc.OAEP_SHA256()
	cbcEnc.BlockCipher = xmlenc.AES128CBC
	sha1Enc := xmlenc.OAEP()
	sha1Enc.BlockCipher = xmlenc.AES256GCM
	pkcs1 := xmlenc.PKCS1v15()
	pkcs1.BlockCipher = xmlenc.AES256GCM
	sps := samlidp.StaticServiceProviders()
	for _, tc := range []struct {
		name string
		enc  xmlenc.Encrypter
		opts []samlidp.Option
		ok   bool
	}{
		{"CBC", cbcEnc, nil, false},
		{"CBC enabled", cbcEnc, []samlidp.Option{samlidp.EnableInsecureAESCBC}, true},
		{"mgf1p", sha1Enc, nil, false},
		{"mgf1p enabled", sha1Enc, []samlidp.Option{samlidp.EnableInsecureRSAOAEPSHA1}, true},
		{"PKCS#1 v1.5", pkcs1, []samlidp.Option{samlidp.EnableInsecureAESCBC, samlidp.EnableInsecureRSAOAEPSHA1}, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set := samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.LogoutNameIDEncrypter = tc.enc })
			_, err := samlidp.New(idpEntityID, sps, append([]samlidp.Option{samlidp.WithSigningKey(idpKey, idpCert), set}, tc.opts...)...)
			if (err == nil) != tc.ok {
				t.Fatalf("New: %v", err)
			}
		})
	}

	// Set for one Response only, it is checked when it is used.
	p := newPair(t, nil, []samlsp.Option{samlsp.WithEncryptionKey(spKey, spCert)})
	_, _, _, err := p.tryRespond(t, testSubject, samlidp.WithIdentityProvider(func(idp *saml.IdentityProvider) { idp.AssertionEncrypter = cbcEnc }))
	if err == nil || !strings.Contains(err.Error(), "EnableInsecureAESCBC") {
		t.Fatalf("got %v, want the CBC encrypter refused", err)
	}
}
