// Package fuzz holds fuzz tests for github.com/crewjam/saml that OSS-Fuzz
// runs continuously (see oss_fuzz_build.sh). They drive only the public API
// with attacker-controlled bytes, against a ServiceProvider configured from
// the repository's test fixtures. They live in their own package, with no
// other tests, because the OSS-Fuzz Go toolchain compiles every _test.go file
// in a fuzzer's package against its own testing shim. Run one locally with
//
//	go test -fuzz=FuzzParseXMLResponse ./fuzz
package fuzz

import (
	"crypto/rsa"
	"crypto/x509"
	_ "embed"
	"encoding/pem"
	"encoding/xml"
	"io"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/xmlenc"
)

// Copies of the fixtures of the same name in the repository's testdata/.
var (
	//go:embed testdata/sp_key.pem
	spKeyPEM []byte
	//go:embed testdata/sp_cert.pem
	spCertPEM []byte
	//go:embed testdata/SP_IDPMetadata
	idpMetadataXML []byte
)

// The request ID SP_SamlResponse answers, and the time it was issued.
const requestID = "id-9e61753d64e928af5a7a341a97f420c9"

var (
	spKey  *rsa.PrivateKey
	spCert *x509.Certificate
	now    = time.Date(2015, time.December, 1, 1, 57, 9, 0, time.UTC)
)

func init() {
	block, _ := pem.Decode(spKeyPEM)
	key, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		panic(err)
	}
	spKey = key
	block, _ = pem.Decode(spCertPEM)
	if spCert, err = x509.ParseCertificate(block.Bytes); err != nil {
		panic(err)
	}
}

func mustParseURL(s string) url.URL {
	u, err := url.Parse(s)
	if err != nil {
		panic(err)
	}
	return *u
}

// newSP returns a ServiceProvider that trusts the IdP in SP_IDPMetadata. A new
// one per input keeps state such as the replay cache from leaking between runs.
func newSP() *saml.ServiceProvider {
	sp := &saml.ServiceProvider{
		Key:         spKey,
		Certificate: spCert,
		MetadataURL: mustParseURL("https://15661444.ngrok.io/saml2/metadata"),
		AcsURL:      mustParseURL("https://15661444.ngrok.io/saml2/acs"),
		SloURL:      mustParseURL("https://15661444.ngrok.io/saml2/slo"),
		IDPMetadata: &saml.EntityDescriptor{},
		Clock:       dsig.NewFakeClockAt(now),
	}
	if err := xml.Unmarshal(idpMetadataXML, sp.IDPMetadata); err != nil {
		panic(err)
	}
	return sp
}

// FuzzParseXMLResponse feeds a decoded SAMLResponse to the SP's assertion
// validation: signature checks, decryption and condition checks.
func FuzzParseXMLResponse(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data []byte) {
		sp := newSP()
		_, _ = sp.ParseXMLResponse(data, []string{requestID}, sp.AcsURL)
	})
}

// FuzzParseXMLArtifactResponse feeds a SOAP ArtifactResponse to the SP.
func FuzzParseXMLArtifactResponse(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data []byte) {
		sp := newSP()
		_, _ = sp.ParseXMLArtifactResponse(data, []string{requestID}, "id-artifact", sp.AcsURL)
	})
}

// FuzzLogoutRequest feeds an HTTP-POST LogoutRequest form value to the SP.
func FuzzLogoutRequest(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data string) {
		_, _ = newSP().ValidateLogoutRequestForm(data)
	})
}

// FuzzLogoutResponseRedirect feeds an HTTP-Redirect LogoutResponse query
// string (deflated, base64, detached signature) to the SP.
func FuzzLogoutResponseRedirect(f *testing.F) {
	f.Add("SAMLResponse=&RelayState=&SigAlg=&Signature=")
	f.Fuzz(func(_ *testing.T, query string) {
		sp := newSP()
		u := sp.SloURL
		u.RawQuery = query
		req := &http.Request{Method: http.MethodGet, URL: &u, Header: http.Header{}}
		_, _ = sp.ParseLogoutResponse(req, []string{requestID})
	})
}

// FuzzLogoutResponseForm feeds an urlencoded HTTP-POST (or POST-SimpleSign)
// LogoutResponse body to the SP.
func FuzzLogoutResponseForm(f *testing.F) {
	f.Add("SAMLResponse=")
	f.Add("SAMLResponse=&RelayState=&SigAlg=&Signature=")
	f.Fuzz(func(_ *testing.T, body string) {
		sp := newSP()
		u := sp.SloURL
		req := &http.Request{
			Method: http.MethodPost,
			URL:    &u,
			Header: http.Header{"Content-Type": {"application/x-www-form-urlencoded"}},
			Body:   io.NopCloser(strings.NewReader(body)),
		}
		_, _ = sp.ParseLogoutResponse(req, []string{requestID})
	})
}

// FuzzUnmarshal decodes data as each of the protocol and metadata types the
// library reads from peers, then re-encodes whatever it accepted.
func FuzzUnmarshal(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data []byte) {
		for _, v := range []any{
			&saml.EntityDescriptor{},
			&saml.EntitiesDescriptor{},
			&saml.AuthnRequest{},
			&saml.LogoutRequest{},
			&saml.LogoutResponse{},
			&saml.Response{},
			&saml.Assertion{},
			&saml.ArtifactResolve{},
			&saml.ArtifactResponse{},
			&saml.AttributeQuery{},
		} {
			if xml.Unmarshal(data, v) == nil {
				_, _ = xml.Marshal(v)
			}
		}
	})
}

// FuzzDecrypt decrypts the root element of data with the SP's key.
func FuzzDecrypt(f *testing.F) {
	f.Fuzz(func(_ *testing.T, data []byte) {
		doc := etree.NewDocument()
		if doc.ReadFromBytes(data) != nil || doc.Root() == nil {
			return
		}
		_, _ = xmlenc.Decrypt(spKey, doc.Root())
	})
}
