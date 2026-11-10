package samlsp_test

import (
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// spKeys returns the certificates of the SP metadata md for use, in order.
func spKeys(t *testing.T, md *saml.EntityDescriptor, use string) []*x509.Certificate {
	t.Helper()
	var certs []*x509.Certificate
	for _, kd := range md.SPSSODescriptors[0].KeyDescriptors {
		if kd.Use != use {
			continue
		}
		for _, c := range kd.KeyInfo.X509Data.X509Certificates {
			der, err := base64.StdEncoding.DecodeString(c.Data)
			if err != nil {
				t.Fatal(err)
			}
			cert, err := x509.ParseCertificate(der)
			if err != nil {
				t.Fatal(err)
			}
			certs = append(certs, cert)
		}
	}
	return certs
}

func sameCerts(got []*x509.Certificate, want ...*x509.Certificate) bool {
	return slices.EqualFunc(got, want, func(a, b *x509.Certificate) bool { return a.Equal(b) })
}

func TestNextCertificatesInMetadata(t *testing.T) {
	ti := newTestIDP(t)
	sigKey, sigCert := newKeyPair(t, "signing")
	_, nextSigCert := newKeyPair(t, "next signing")
	_, nextECCert := newECKeyPair(t)
	encKey, encCert := newKeyPair(t, "encryption")
	nextEncKey, nextEncCert := newKeyPair(t, "next encryption")

	cfg, err := samlsp.New(spEntityID, staticIDP(ti),
		samlsp.WithSigningKey(sigKey, sigCert),
		samlsp.WithEncryptionKey(encKey, encCert),
		// The current certificates are not listed twice.
		samlsp.WithNextSigningCertificates(sigCert, nextSigCert, nextECCert, nextSigCert),
		samlsp.WithNextEncryptionCertificates(encCert, nextEncCert),
		samlsp.WithDecryptionKeys(nextEncKey))
	if err != nil {
		t.Fatal(err)
	}
	md := cfg.Metadata(t.Context())
	if got := spKeys(t, md, "signing"); !sameCerts(got, sigCert, nextSigCert, nextECCert) {
		t.Errorf("signing certificates: got %d, want the current one, then the next ones", len(got))
	}
	if got := spKeys(t, md, "encryption"); !sameCerts(got, encCert, nextEncCert) {
		t.Errorf("encryption certificates: got %d, want the current one, then the next one", len(got))
	}
	var methods [][]saml.EncryptionMethod
	for _, kd := range md.SPSSODescriptors[0].KeyDescriptors {
		if kd.Use == "encryption" {
			methods = append(methods, kd.EncryptionMethods)
		}
	}
	if len(methods) != 2 || len(methods[0]) == 0 || !slices.Equal(methods[0], methods[1]) {
		t.Errorf("the next encryption key does not offer the same methods: %v", methods)
	}
}

func TestNextCertificatesErrors(t *testing.T) {
	ti := newTestIDP(t)
	sigKey, sigCert := newKeyPair(t, "signing")
	encKey, encCert := newKeyPair(t, "encryption")
	nextKey, nextCert := newKeyPair(t, "next")
	_, ecCert := newECKeyPair(t)

	for name, opts := range map[string][]samlsp.Option{
		"next encryption without its key": {
			samlsp.WithEncryptionKey(encKey, encCert),
			samlsp.WithNextEncryptionCertificates(nextCert),
		},
		"next encryption without any key": {
			samlsp.WithNextEncryptionCertificates(nextCert),
		},
		"next encryption with another decryption key": {
			samlsp.WithNextEncryptionCertificates(nextCert),
			samlsp.WithDecryptionKeys(encKey),
		},
		"next encryption not RSA": {
			samlsp.WithEncryptionKey(encKey, encCert),
			samlsp.WithNextEncryptionCertificates(ecCert),
		},
		"nil next encryption": {
			samlsp.WithNextEncryptionCertificates(nil),
		},
		"nil next signing": {
			samlsp.WithNextSigningCertificates(nil),
		},
	} {
		opts = append([]samlsp.Option{samlsp.WithSigningKey(sigKey, sigCert)}, opts...)
		if _, err := samlsp.New(spEntityID, staticIDP(ti), opts...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}

	for name, opts := range map[string][]samlsp.Option{
		"next key in WithDecryptionKeys": {
			samlsp.WithEncryptionKey(encKey, encCert),
			samlsp.WithNextEncryptionCertificates(nextCert),
			samlsp.WithDecryptionKeys(nextKey),
		},
		"next key in WithDecryptionKeys, no current key": {
			samlsp.WithNextEncryptionCertificates(nextCert),
			samlsp.WithDecryptionKeys(nextKey),
		},
		// After the switch, the previous certificate stays published.
		"previous key": {
			samlsp.WithEncryptionKey(nextKey, nextCert),
			samlsp.WithNextEncryptionCertificates(encCert),
			samlsp.WithDecryptionKeys(encKey),
		},
		"ECDSA next signing": {
			samlsp.WithNextSigningCertificates(ecCert),
		},
	} {
		opts = append([]samlsp.Option{samlsp.WithSigningKey(sigKey, sigCert)}, opts...)
		if _, err := samlsp.New(spEntityID, staticIDP(ti), opts...); err != nil {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// TestSignedMetadataWithNextCertificates checks that metadata with extra
// KeyDescriptors is signed, by the current key only, and that the
// signature covers them.
func TestSignedMetadataWithNextCertificates(t *testing.T) {
	ti := newTestIDP(t)
	sigKey, sigCert := newKeyPair(t, "signing")
	nextKey, nextCert := newKeyPair(t, "next")
	cfg, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.SignMetadata,
		samlsp.WithSigningKey(sigKey, sigCert),
		samlsp.WithNextSigningCertificates(nextCert),
		samlsp.WithNextEncryptionCertificates(nextCert),
		samlsp.WithDecryptionKeys(nextKey))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := cfg.MetadataXML(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	signed, err := saml.VerifyMetadataSignatureRejectSHA1(buf, []*x509.Certificate{sigCert})
	if err != nil {
		t.Fatalf("the metadata is not signed by the current key: %v", err)
	}
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(signed, &md); err != nil {
		t.Fatal(err)
	}
	if got := spKeys(t, &md, "signing"); !sameCerts(got, sigCert, nextCert) {
		t.Errorf("signed signing certificates: got %d", len(got))
	}
	if got := spKeys(t, &md, "encryption"); !sameCerts(got, nextCert) {
		t.Errorf("signed encryption certificates: got %d", len(got))
	}
	if _, err := saml.VerifyMetadataSignatureRejectSHA1(buf, []*x509.Certificate{nextCert}); err == nil {
		t.Error("the metadata verified with the next certificate")
	}

	// Removing a next certificate breaks the signature.
	data := base64.StdEncoding.EncodeToString(nextCert.Raw)
	tampered := strings.Replace(string(buf), data, "", 1)
	if _, err := saml.VerifyMetadataSignatureRejectSHA1([]byte(tampered), []*x509.Certificate{sigCert}); err == nil {
		t.Error("metadata without a next certificate still verified")
	}
}

// sendAuthnRequest sends msg to ti's SSO service and returns the error it
// refused it with, if any.
func sendAuthnRequest(t *testing.T, ti *testIDP, msg *samlsp.Message) error {
	t.Helper()
	var refused error
	ti.idp.OnError = func(_ http.ResponseWriter, _ *http.Request, _ int, err error) { refused = err }
	var r *http.Request
	if u := msg.RedirectURL(); u != nil {
		r = httptest.NewRequest(http.MethodGet, u.String(), nil)
	} else {
		w := httptest.NewRecorder()
		msg.Write(w)
		r = postForm(msg.Destination, formValues(w.Body.String()))
	}
	w := httptest.NewRecorder()
	ti.idp.ServeSSO(w, r)
	if refused == nil && w.Code != http.StatusOK {
		refused = fmt.Errorf("status %d", w.Code)
	}
	return refused
}

// TestSigningKeyRollover rotates the key that signs AuthnRequests, with an
// IdP that wants them signed: once the IdP has the metadata with the next
// certificate, it accepts requests signed with either key.
func TestSigningKeyRollover(t *testing.T) {
	for _, binding := range []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding} {
		t.Run(binding, func(t *testing.T) {
			ti := newTestIDP(t)
			ti.idp.WantAuthnRequestsSigned = true
			oldKey, oldCert := newKeyPair(t, "old")
			nextKey, nextCert := newKeyPair(t, "next")
			newConfig := func(opts ...samlsp.Option) *samlsp.Config {
				t.Helper()
				cfg, err := samlsp.New(spEntityID, staticIDP(ti), append(opts, samlsp.SignAuthnRequests)...)
				if err != nil {
					t.Fatal(err)
				}
				return cfg
			}
			send := func(cfg *samlsp.Config) error {
				t.Helper()
				msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithBinding(binding))
				if err != nil {
					t.Fatal(err)
				}
				return sendAuthnRequest(t, ti, msg)
			}

			before := newConfig(samlsp.WithSigningKey(oldKey, oldCert))
			published := newConfig(samlsp.WithSigningKey(oldKey, oldCert), samlsp.WithNextSigningCertificates(nextCert))
			switched := newConfig(samlsp.WithSigningKey(nextKey, nextCert), samlsp.WithNextSigningCertificates(oldCert))

			// The IdP has the metadata from before the rotation: a
			// request signed with the next key is refused.
			ti.spMeta = before.Metadata(t.Context())
			if err := send(switched); !errors.Is(err, saml.ErrInvalidSignature) && !errors.Is(err, saml.ErrUntrustedCertificate) {
				t.Fatalf("a request signed with a key the IdP was never given: got %v", err)
			}

			// The IdP refreshes the metadata with the next certificate:
			// requests signed with either key are accepted.
			ti.spMeta = published.Metadata(t.Context())
			if err := send(published); err != nil {
				t.Errorf("request signed with the current key: %v", err)
			}
			if err := send(switched); err != nil {
				t.Errorf("request signed with the next key: %v", err)
			}

			// After the switch, the metadata still lists the old key.
			ti.spMeta = switched.Metadata(t.Context())
			if err := send(before); err != nil {
				t.Errorf("request signed with the previous key after the switch: %v", err)
			}
			if err := send(switched); err != nil {
				t.Errorf("request signed with the new key after the switch: %v", err)
			}
		})
	}
}

// TestEncryptionKeyRollover: once the metadata lists the next encryption
// certificate, an IdP may encrypt to it at once, before the SP switches;
// the key of WithDecryptionKeys decrypts.
func TestEncryptionKeyRollover(t *testing.T) {
	ti := newTestIDP(t)
	encKey, encCert := newKeyPair(t, "encryption")
	nextKey, nextCert := newKeyPair(t, "next encryption")
	cfg := newTestConfig(t, ti,
		samlsp.WithEncryptionKey(encKey, encCert),
		samlsp.WithNextEncryptionCertificates(nextCert),
		samlsp.WithDecryptionKeys(nextKey))

	// Package saml's IdP encrypts to the first encryption key; drop the
	// current one, as for an IdP that picks the last.
	md := cfg.Metadata(t.Context())
	sp := &md.SPSSODescriptors[0]
	sp.KeyDescriptors = slices.DeleteFunc(sp.KeyDescriptors, func(kd saml.KeyDescriptor) bool {
		return kd.Use == "encryption" && kd.KeyInfo.X509Data.X509Certificates[0].Data == base64.StdEncoding.EncodeToString(encCert.Raw)
	})
	if got := spKeys(t, md, "encryption"); !sameCerts(got, nextCert) {
		t.Fatalf("encryption certificates: got %d", len(got))
	}
	ti.spMeta = md

	msg, err := cfg.AuthnRequest(t.Context(), "s")
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)
	if !strings.Contains(decodedResponse(t, acs), "EncryptedAssertion") {
		t.Fatal("the IdP did not encrypt the assertion")
	}
	if _, err := cfg.ParseResponse(t.Context(), acs, samlsp.WithRequestID(msg.ID)); err != nil {
		t.Fatalf("ParseResponse: %v (%v)", err, errors.Unwrap(err))
	}
}
