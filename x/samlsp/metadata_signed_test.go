package samlsp_test

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// signedIDPMetadata returns ti's metadata, signed by ti's key.
func signedIDPMetadata(t *testing.T, ti *testIDP) []byte {
	t.Helper()
	el, err := ti.idp.SignedMetadata()
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return buf
}

// signedAggregate returns an EntitiesDescriptor of entities, signed with key.
func signedAggregate(t *testing.T, key *rsa.PrivateKey, cert *x509.Certificate, entities ...*saml.EntityDescriptor) []byte {
	t.Helper()
	id := "id-aggregate"
	agg := saml.EntitiesDescriptor{ID: &id}
	for _, e := range entities {
		agg.EntityDescriptors = append(agg.EntityDescriptors, *e)
	}
	buf, err := xml.Marshal(agg)
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(buf); err != nil {
		t.Fatal(err)
	}
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: key, Certificate: [][]byte{cert.Raw}})
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
		t.Fatal(err)
	}
	signed, err := signer.SignEnveloped(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	out := etree.NewDocument()
	out.SetRoot(signed)
	b, err := out.WriteToBytes()
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestSignedMetadata(t *testing.T) {
	ti := newTestIDP(t)
	signed := signedIDPMetadata(t, ti)
	unsigned, err := xml.Marshal(ti.idp.Metadata())
	if err != nil {
		t.Fatal(err)
	}
	_, otherCert := newKeyPair(t, "other")
	// Tampered: the SSO location changed after signing.
	tampered := []byte(strings.Replace(string(signed), "https://idp.example.com/sso", "https://evil.example.com/sso", 1))
	if string(tampered) == string(signed) {
		t.Fatal("the test did not tamper with the metadata")
	}

	for _, tt := range []struct {
		name  string
		data  []byte
		certs []*x509.Certificate
		ok    bool
	}{
		{"signed, right certificate", signed, []*x509.Certificate{ti.cert}, true},
		{"signed, one of several certificates", signed, []*x509.Certificate{otherCert, ti.cert}, true},
		{"signed, wrong certificate", signed, []*x509.Certificate{otherCert}, false},
		{"unsigned", unsigned, []*x509.Certificate{ti.cert}, false},
		{"tampered", tampered, []*x509.Certificate{ti.cert}, false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			check := func(f samlsp.MetadataFunc) {
				t.Helper()
				md, err := f(t.Context())
				if tt.ok && (err != nil || md.EntityID != "https://idp.example.com/metadata") {
					t.Errorf("got %v, %v", md, err)
				}
				if !tt.ok && err == nil {
					t.Error("accepted")
				}
			}
			check(samlsp.StaticMetadataBytes(tt.data, samlsp.WithMetadataSigners(tt.certs...)))

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write(tt.data) }))
			defer srv.Close()
			check(samlsp.RemoteMetadata(srv.URL, samlsp.WithHTTPClient(srv.Client()), samlsp.WithMetadataSigners(tt.certs...)))
			check(samlsp.MDQMetadata(srv.URL, "https://idp.example.com/metadata",
				samlsp.WithHTTPClient(srv.Client()), samlsp.WithMetadataSigners(tt.certs...)))
		})
	}

	// A Config with signed metadata that fails refuses to build requests.
	cfg := newTestConfigWithIDP(t, ti, samlsp.StaticMetadataBytes(signed, samlsp.WithMetadataSigners(otherCert)))
	if _, err := cfg.AuthnRequest(t.Context(), "s"); err == nil {
		t.Error("AuthnRequest with metadata signed by an untrusted key")
	}
}

func TestSignedAggregate(t *testing.T) {
	ti := newTestIDP(t)
	other := newTestIDP(t)
	other.idp.MetadataURL = mustURL("https://idp2.example.com/metadata")
	fedKey, fedCert := newKeyPair(t, "federation")
	_, wrongCert := newKeyPair(t, "wrong")
	agg := signedAggregate(t, fedKey, fedCert, ti.idp.Metadata(), other.idp.Metadata())

	// The entity asked for, under the federation's signature.
	md, err := samlsp.StaticMetadataBytes(agg,
		samlsp.WithIdentityProviderEntityID("https://idp2.example.com/metadata"),
		samlsp.WithMetadataSigners(fedCert))(t.Context())
	if err != nil || md.EntityID != "https://idp2.example.com/metadata" {
		t.Fatalf("got %v, %v", md, err)
	}

	for name, f := range map[string]samlsp.MetadataFunc{
		"wrong certificate": samlsp.StaticMetadataBytes(agg,
			samlsp.WithIdentityProviderEntityID("https://idp2.example.com/metadata"), samlsp.WithMetadataSigners(wrongCert)),
		"unknown entity": samlsp.StaticMetadataBytes(agg,
			samlsp.WithIdentityProviderEntityID("https://idp3.example.com/metadata"), samlsp.WithMetadataSigners(fedCert)),
		// Two IdPs, and no entity ID to choose one.
		"no entity ID": samlsp.StaticMetadataBytes(agg, samlsp.WithMetadataSigners(fedCert)),
	} {
		if _, err := f(t.Context()); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
	_, err = samlsp.StaticMetadataBytes(agg, samlsp.WithMetadataSigners(fedCert))(t.Context())
	if err == nil || !strings.Contains(err.Error(), "WithIdentityProviderEntityID") {
		t.Errorf("the error for several IdPs does not name the option: %v", err)
	}
}
