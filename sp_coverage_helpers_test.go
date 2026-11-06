package saml

import (
	"bytes"
	"compress/flate"
	"crypto"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/golden"

	"github.com/crewjam/saml/xmlenc"
)

const (
	spcovIDPEntityID      = "https://idp.example.com/metadata"
	spcovRequestID        = "id-request"
	spcovArtifactLocation = "https://idp.example.com/artifact"
)

// spcovNow is inside the validity period of testdata/idp_cert.pem and sp_cert.pem.
var spcovNow = time.Date(2014, 1, 1, 0, 0, 0, 0, time.UTC)

type spcovEnv struct {
	sp      *ServiceProvider
	idpKey  *rsa.PrivateKey
	idpCert *x509.Certificate
}

// spcovSetup pins TimeNow, Clock and RandReader (restoring them afterwards) and
// returns a service provider that trusts a programmatically built IDP.
func spcovSetup(t *testing.T) *spcovEnv {
	t.Helper()
	oldTimeNow, oldClock, oldRandReader := TimeNow, Clock, RandReader
	t.Cleanup(func() {
		TimeNow, Clock, RandReader = oldTimeNow, oldClock, oldRandReader
	})
	TimeNow = func() time.Time { return spcovNow }
	Clock = dsig.NewFakeClockAt(spcovNow)
	RandReader = &testRandomReader{}

	idpKey := mustParsePrivateKey(golden.Get(t, "idp_key.pem")).(*rsa.PrivateKey)
	idpCert := mustParseCertificate(golden.Get(t, "idp_cert.pem"))
	sp := &ServiceProvider{
		Key:         mustParsePrivateKey(golden.Get(t, "sp_key.pem")).(*rsa.PrivateKey),
		Certificate: mustParseCertificate(golden.Get(t, "sp_cert.pem")),
		MetadataURL: mustParseURL("https://sp.example.com/saml/metadata"),
		AcsURL:      mustParseURL("https://sp.example.com/saml/acs"),
		SloURL:      mustParseURL("https://sp.example.com/saml/slo"),
		IDPMetadata: spcovIDPMetadata(idpCert),
	}
	return &spcovEnv{sp: sp, idpKey: idpKey, idpCert: idpCert}
}

func spcovIDPMetadata(cert *x509.Certificate) *EntityDescriptor {
	return &EntityDescriptor{
		EntityID: spcovIDPEntityID,
		IDPSSODescriptors: []IDPSSODescriptor{{
			SSODescriptor: SSODescriptor{
				RoleDescriptor: RoleDescriptor{
					KeyDescriptors: []KeyDescriptor{{
						Use: "signing",
						KeyInfo: KeyInfo{X509Data: X509Data{X509Certificates: []X509Certificate{
							{Data: base64.StdEncoding.EncodeToString(cert.Raw)},
						}}},
					}},
				},
				SingleLogoutServices: []Endpoint{
					{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/slo/redirect"},
					{Binding: HTTPPostBinding, Location: "https://idp.example.com/slo/post"},
				},
			},
			SingleSignOnServices: []Endpoint{
				{Binding: HTTPRedirectBinding, Location: "https://idp.example.com/sso/redirect"},
				{Binding: HTTPPostBinding, Location: "https://idp.example.com/sso/post"},
			},
			ArtifactResolutionServices: []Endpoint{
				{Binding: SOAPBinding, Location: spcovArtifactLocation},
			},
		}},
	}
}

// spcovSign returns el with an enveloped signature made by key, embedding cert in KeyInfo.
func spcovSign(t *testing.T, key crypto.Signer, cert *x509.Certificate, el *etree.Element) *etree.Element {
	t.Helper()
	ctx, err := dsig.NewSigningContext(key, [][]byte{cert.Raw})
	assert.NilError(t, err)
	ctx.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	assert.NilError(t, ctx.SetSignatureMethod(dsig.RSASHA256SignatureMethod))
	signed, err := ctx.SignEnveloped(el)
	assert.NilError(t, err)
	return signed
}

func (e *spcovEnv) idpSign(t *testing.T, el *etree.Element) *etree.Element {
	t.Helper()
	return spcovSign(t, e.idpKey, e.idpCert, el)
}

func (e *spcovEnv) assertion() *Assertion {
	return &Assertion{
		ID:           "id-assertion",
		IssueInstant: spcovNow,
		Version:      "2.0",
		Issuer:       Issuer{Value: spcovIDPEntityID},
		Subject: &Subject{
			NameID: &NameID{Value: "alice@example.com"},
			SubjectConfirmations: []SubjectConfirmation{{
				Method: bearerSubjectConfirmationMethod,
				SubjectConfirmationData: &SubjectConfirmationData{
					InResponseTo: spcovRequestID,
					Recipient:    e.sp.AcsURL.String(),
					NotOnOrAfter: spcovNow.Add(5 * time.Minute),
				},
			}},
		},
		Conditions: &Conditions{
			NotBefore:    spcovNow.Add(-time.Minute),
			NotOnOrAfter: spcovNow.Add(5 * time.Minute),
			AudienceRestrictions: []AudienceRestriction{
				{Audience: Audience{Value: e.sp.MetadataURL.String()}},
			},
		},
	}
}

func (e *spcovEnv) response() *Response {
	return &Response{
		ID:           "id-response",
		InResponseTo: spcovRequestID,
		Version:      "2.0",
		IssueInstant: spcovNow,
		Destination:  e.sp.AcsURL.String(),
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
	}
}

func (e *spcovEnv) logoutResponse() *LogoutResponse {
	return &LogoutResponse{
		ID:           "id-logout-response",
		InResponseTo: "id-logout-request",
		Version:      "2.0",
		IssueInstant: spcovNow,
		Destination:  e.sp.SloURL.String(),
		Issuer:       &Issuer{Value: spcovIDPEntityID},
		Status:       Status{StatusCode: StatusCode{Value: StatusSuccess}},
	}
}

// encryptedAssertion encrypts plaintext for the SP and wraps it in an EncryptedAssertion.
func (e *spcovEnv) encryptedAssertion(t *testing.T, plaintext []byte) *etree.Element {
	t.Helper()
	encryptor := xmlenc.OAEP()
	encryptor.BlockCipher = xmlenc.AES128CBC
	encryptor.DigestMethod = &xmlenc.SHA1
	encryptedDataEl, err := encryptor.Encrypt(e.sp.Certificate, plaintext, nil)
	assert.NilError(t, err)
	encryptedDataEl.CreateAttr("Type", "http://www.w3.org/2001/04/xmlenc#Element")
	el := etree.NewElement("saml:EncryptedAssertion")
	el.CreateAttr("xmlns:saml", "urn:oasis:names:tc:SAML:2.0:assertion")
	el.AddChild(encryptedDataEl)
	return el
}

func spcovSerialize(t *testing.T, el *etree.Element) []byte {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot(el)
	buf, err := doc.WriteToBytes()
	assert.NilError(t, err)
	return buf
}

func spcovParse(t *testing.T, s string) *etree.Element {
	t.Helper()
	doc := etree.NewDocument()
	assert.NilError(t, doc.ReadFromString(s))
	return doc.Root()
}

func spcovDeflate(t *testing.T, buf []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	w, err := flate.NewWriter(&out, flate.BestCompression)
	assert.NilError(t, err)
	_, err = w.Write(buf)
	assert.NilError(t, err)
	assert.NilError(t, w.Close())
	return out.Bytes()
}

func spcovSOAPEnvelope(body *etree.Element) *etree.Element {
	env := etree.NewElement("soapenv:Envelope")
	env.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	env.CreateElement("soapenv:Body").AddChild(body)
	return env
}

// spcovPrivateErr asserts err is an *InvalidResponseError and returns its PrivateErr.
func spcovPrivateErr(t *testing.T, err error) error {
	t.Helper()
	var ire *InvalidResponseError
	assert.Assert(t, errors.As(err, &ire), "expected *InvalidResponseError, got %T: %v", err, err)
	assert.Equal(t, "Authentication failed", ire.Error())
	return ire.PrivateErr
}

// spcovBrokenKey returns an *rsa.PrivateKey that passes type checks but whose
// private operations fail (N does not equal P*Q).
func spcovBrokenKey(key *rsa.PrivateKey) *rsa.PrivateKey {
	return &rsa.PrivateKey{
		PublicKey: rsa.PublicKey{N: new(big.Int).Add(key.N, big.NewInt(2)), E: key.E},
		D:         key.D,
		Primes:    key.Primes,
	}
}

type spcovRoundTripper func(*http.Request) (*http.Response, error)

func (f spcovRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) { return f(req) }

// spcovBody is an io.ReadCloser whose Read and Close can be made to fail.
type spcovBody struct {
	r        *bytes.Reader
	readErr  error
	closeErr error
}

func (b *spcovBody) Read(p []byte) (int, error) {
	if b.readErr != nil {
		return 0, b.readErr
	}
	return b.r.Read(p)
}

func (b *spcovBody) Close() error { return b.closeErr }

type spcovVerifier struct {
	err    error
	called bool
}

func (v *spcovVerifier) VerifySignature(_ *dsig.ValidationContext, _ *etree.Element) error {
	v.called = true
	return v.err
}
