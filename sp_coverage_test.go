package saml

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"strings"
	"testing"
	"time"

	dsig "github.com/russellhaering/goxmldsig"
	"github.com/russellhaering/goxmldsig/etreeutils"
	"gotest.tools/assert"
	is "gotest.tools/assert/cmp"
)

func TestSpcovNameIDFormatElement(t *testing.T) {
	el := EmailAddressNameIDFormat.Element()
	assert.Equal(t, "", el.Tag)
	assert.Equal(t, string(EmailAddressNameIDFormat), el.Text())
}

func TestSpcovAssertionAttributesGet(t *testing.T) {
	aa := AssertionAttributes{
		{FriendlyName: "mail", Name: "urn:oid:0.9.2342.19200300.100.1.3", Value: "alice@example.com"},
		{FriendlyName: "cn", Name: "urn:oid:2.5.4.3", Value: "Alice"},
	}
	byName := aa.Get("urn:oid:2.5.4.3")
	assert.Assert(t, byName != nil)
	assert.Equal(t, "Alice", byName.Value)

	byFriendlyName := aa.Get("mail")
	assert.Assert(t, byFriendlyName != nil)
	assert.Equal(t, "alice@example.com", byFriendlyName.Value)

	// the returned pointer must not alias the slice element
	byFriendlyName.Value = "changed"
	assert.Equal(t, "alice@example.com", aa[0].Value)

	assert.Assert(t, is.Nil(aa.Get("missing")))
}

func TestSpcovInvalidResponseErrorHidesDetails(t *testing.T) {
	err := &InvalidResponseError{PrivateErr: errors.New("secret detail")}
	assert.Equal(t, "Authentication failed", err.Error())
}

func TestSpcovMetadataValidDurationAndIntermediates(t *testing.T) {
	e := spcovSetup(t)
	e.sp.MetadataValidDuration = time.Hour
	e.sp.Intermediates = []*x509.Certificate{e.idpCert}
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod

	md := e.sp.Metadata()
	assert.Equal(t, spcovNow.Add(time.Hour), md.ValidUntil)
	spsso := md.SPSSODescriptors[0]
	assert.Equal(t, spcovNow.Add(time.Hour), *spsso.ValidUntil)
	assert.Equal(t, 2, len(spsso.KeyDescriptors))

	wantChain := base64.StdEncoding.EncodeToString(append(append([]byte{}, e.sp.Certificate.Raw...), e.idpCert.Raw...))
	for _, kd := range spsso.KeyDescriptors {
		assert.Equal(t, wantChain, kd.KeyInfo.X509Data.X509Certificates[0].Data)
	}
}

func TestSpcovBindingLocationsMissing(t *testing.T) {
	e := spcovSetup(t)
	assert.Equal(t, "", e.sp.GetSSOBindingLocation(SOAPBinding))
	assert.Equal(t, "", e.sp.GetSLOBindingLocation(SOAPBinding))
	assert.Equal(t, "https://idp.example.com/sso/post", e.sp.GetSSOBindingLocation(HTTPPostBinding))
	assert.Equal(t, "https://idp.example.com/slo/post", e.sp.GetSLOBindingLocation(HTTPPostBinding))
}

func TestSpcovGetIDPSigningCertsNoSigningCert(t *testing.T) {
	e := spcovSetup(t)
	e.sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].Use = "encryption"
	certs, err := e.sp.getIDPSigningCerts()
	assert.Check(t, is.Nil(certs))
	assert.Error(t, err, "cannot find any signing certificate in the IDP SSO descriptor")
}

func TestSpcovAuthnRequestRedirect(t *testing.T) {
	e := spcovSetup(t)

	t.Run("destination with query", func(t *testing.T) {
		req, err := e.sp.MakeAuthenticationRequest("https://idp.example.com/sso?tenant=a", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		u, err := req.Redirect("", e.sp)
		assert.NilError(t, err)
		assert.Assert(t, strings.HasPrefix(u.RawQuery, "tenant=a&SAMLRequest="), u.RawQuery)
		assert.Assert(t, !strings.Contains(u.RawQuery, "RelayState"))
	})

	t.Run("bad destination", func(t *testing.T) {
		req, err := e.sp.MakeAuthenticationRequest("://bad", HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		u, err := req.Redirect("state", e.sp)
		assert.Check(t, is.Nil(u))
		assert.Error(t, err, `parse "://bad": missing protocol scheme`)
	})

	t.Run("bad signature method", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = "bogus"
		u, err := sp.MakeRedirectAuthenticationRequest("state")
		assert.Check(t, is.Nil(u))
		assert.Error(t, err, "invalid signing method bogus")
	})

	t.Run("signing failure", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		sp.Key = spcovBrokenKey(e.sp.Key.(*rsa.PrivateKey))
		u, err := sp.MakeRedirectAuthenticationRequest("state")
		assert.Check(t, is.Nil(u))
		assert.Error(t, err, "crypto/rsa: p * q != n")
	})
}

func TestSpcovGetSigningContext(t *testing.T) {
	e := spcovSetup(t)
	ecKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	assert.NilError(t, err)

	t.Run("rsa method with ecdsa key", func(t *testing.T) {
		sp := *e.sp
		sp.Key = ecKey
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		_, err := GetSigningContext(&sp)
		assert.Error(t, err, "signature method "+dsig.RSASHA256SignatureMethod+" requires a key of type rsa.PrivateKey, not *ecdsa.PrivateKey")
	})

	t.Run("ecdsa method with rsa key", func(t *testing.T) {
		sp := *e.sp
		sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		_, err := GetSigningContext(&sp)
		assert.Error(t, err, "signature method "+dsig.ECDSASHA256SignatureMethod+" requires a key of type ecdsa.PrivateKey, not *rsa.PrivateKey")
	})

	t.Run("ecdsa method with ecdsa key", func(t *testing.T) {
		sp := *e.sp
		sp.Key = ecKey
		sp.SignatureMethod = dsig.ECDSASHA256SignatureMethod
		ctx, err := GetSigningContext(&sp)
		assert.NilError(t, err)
		sig, err := ctx.SignString("hello")
		assert.NilError(t, err)
		assert.Assert(t, len(sig) > 0)
	})

	t.Run("nil certificate", func(t *testing.T) {
		sp := *e.sp
		sp.Certificate = nil
		sp.SignatureMethod = dsig.RSASHA256SignatureMethod
		_, err := GetSigningContext(&sp)
		assert.Error(t, err, "cannot sign: ServiceProvider.Certificate is nil")
		// previously this was a nil pointer dereference
		_, err = sp.MakeAuthenticationRequest("https://idp.example.com/sso", HTTPPostBinding, HTTPPostBinding)
		assert.Error(t, err, "cannot sign: ServiceProvider.Certificate is nil")
	})
}

// TestSpcovSigningErrors covers the error propagation of every Sign*/Make* helper,
// both for a configuration error (GetSigningContext fails) and for a failure of the
// signing operation itself.
func TestSpcovSigningErrors(t *testing.T) {
	e := spcovSetup(t)
	bogus := *e.sp
	bogus.SignatureMethod = "bogus"
	broken := *e.sp
	broken.SignatureMethod = dsig.RSASHA256SignatureMethod
	broken.Key = spcovBrokenKey(e.sp.Key.(*rsa.PrivateKey))

	const bogusErr = "invalid signing method bogus"

	// Sign* with a bad configuration
	assert.Error(t, bogus.SignAuthnRequest(&AuthnRequest{}), bogusErr)
	assert.Error(t, bogus.SignArtifactResolve(&ArtifactResolve{}), bogusErr)
	assert.Error(t, bogus.SignLogoutRequest(&LogoutRequest{}), bogusErr)
	assert.Error(t, bogus.SignLogoutResponse(&LogoutResponse{}), bogusErr)

	// Sign* where the key cannot sign
	for name, err := range map[string]error{
		"SignAuthnRequest":    broken.SignAuthnRequest(&AuthnRequest{ID: "id-1"}),
		"SignArtifactResolve": broken.SignArtifactResolve(&ArtifactResolve{ID: "id-1"}),
		"SignLogoutRequest":   broken.SignLogoutRequest(&LogoutRequest{ID: "id-1"}),
		"SignLogoutResponse":  broken.SignLogoutResponse(&LogoutResponse{ID: "id-1"}),
	} {
		assert.Check(t, is.Error(err, "crypto/rsa: p * q != n"), name)
	}

	// Make* propagate signing errors
	authnReq, err := bogus.MakeAuthenticationRequest("https://idp.example.com/sso", HTTPPostBinding, HTTPPostBinding)
	assert.Check(t, is.Nil(authnReq))
	assert.Check(t, is.Error(err, bogusErr))

	form, err := bogus.MakePostAuthenticationRequest("state")
	assert.Check(t, is.Nil(form))
	assert.Check(t, is.Error(err, bogusErr))

	logoutReq, err := bogus.MakeLogoutRequest("https://idp.example.com/slo", "alice")
	assert.Check(t, is.Nil(logoutReq))
	assert.Check(t, is.Error(err, bogusErr))

	u, err := bogus.MakeRedirectLogoutRequest("alice", "state")
	assert.Check(t, is.Nil(u))
	assert.Check(t, is.Error(err, bogusErr))

	form, err = bogus.MakePostLogoutRequest("alice", "state")
	assert.Check(t, is.Nil(form))
	assert.Check(t, is.Error(err, bogusErr))

	logoutResp, err := bogus.MakeLogoutResponse("https://idp.example.com/slo", "id-req")
	assert.Check(t, is.Nil(logoutResp))
	assert.Check(t, is.Error(err, bogusErr))

	u, err = bogus.MakeRedirectLogoutResponse("id-req", "state")
	assert.Check(t, is.Nil(u))
	assert.Check(t, is.Error(err, bogusErr))

	form, err = bogus.MakePostLogoutResponse("id-req", "state")
	assert.Check(t, is.Nil(form))
	assert.Check(t, is.Error(err, bogusErr))
}

// TestSpcovSignedLogoutMessagesVerify checks that the signatures produced by
// SignLogoutRequest and SignLogoutResponse validate against the SP certificate.
func TestSpcovSignedLogoutMessagesVerify(t *testing.T) {
	e := spcovSetup(t)
	e.sp.SignatureMethod = dsig.RSASHA256SignatureMethod
	validationContext := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{
		Roots: []*x509.Certificate{e.sp.Certificate},
	})
	validationContext.IdAttribute = "ID"
	validationContext.Clock = Clock

	req, err := e.sp.MakeLogoutRequest("https://idp.example.com/slo", "alice")
	assert.NilError(t, err)
	assert.Assert(t, req.Signature != nil)
	_, err = validationContext.Validate(spcovParse(t, string(spcovSerialize(t, req.Element()))))
	assert.NilError(t, err)

	resp, err := e.sp.MakeLogoutResponse("https://idp.example.com/slo", "id-req")
	assert.NilError(t, err)
	assert.Assert(t, resp.Signature != nil)
	_, err = validationContext.Validate(spcovParse(t, string(spcovSerialize(t, resp.Element()))))
	assert.NilError(t, err)

	// tampering with a signed field must break the signature
	resp.InResponseTo = "id-other"
	_, err = validationContext.Validate(spcovParse(t, string(spcovSerialize(t, resp.Element()))))
	assert.Error(t, err, "Signature could not be verified")
}

func TestSpcovFingerprint(t *testing.T) {
	e := spcovSetup(t)
	cert := e.idpCert

	sum256 := sha256.Sum256(cert.Raw)
	fp, err := fingerprint(cert, "http://www.w3.org/2001/04/xmlenc#sha256")
	assert.NilError(t, err)
	assert.Equal(t, spcovColonHex(sum256[:]), fp)

	sum512 := sha512.Sum512(cert.Raw)
	fp, err = fingerprint(cert, "http://www.w3.org/2001/04/xmlenc#sha512")
	assert.NilError(t, err)
	assert.Equal(t, spcovColonHex(sum512[:]), fp)

	_, err = fingerprint(cert, "http://www.w3.org/2000/09/xmldsig#sha1")
	assert.Error(t, err, "fingerprint, unknown algorithm: http://www.w3.org/2000/09/xmldsig#sha1")

	fp, err = fingerprintFormat([]byte{0x0a, 0xff, 0x00})
	assert.NilError(t, err)
	assert.Equal(t, "0A:FF:00", fp)

	fp, err = fingerprintFormat(nil)
	assert.NilError(t, err)
	assert.Equal(t, "", fp)
}

func spcovColonHex(b []byte) string {
	parts := make([]string, len(b))
	for i := range b {
		parts[i] = strings.ToUpper(hex.EncodeToString(b[i : i+1]))
	}
	return strings.Join(parts, ":")
}

func TestSpcovParseCert(t *testing.T) {
	e := spcovSetup(t)
	b64 := base64.StdEncoding.EncodeToString(e.idpCert.Raw)

	// whitespace (as found in metadata) is tolerated
	cert, err := parseCert("\n  " + b64[:20] + "\n\t" + b64[20:] + "  \n")
	assert.NilError(t, err)
	assert.Assert(t, cert.Equal(e.idpCert))

	_, err = parseCert("!!!")
	assert.Error(t, err, "parse cert, cannot base64 decode cert string: illegal base64 data at input byte 0")

	_, err = parseCert(base64.StdEncoding.EncodeToString([]byte("not a certificate")))
	assert.Error(t, err, "parse cert, cannot parse certificate: x509: malformed certificate")
}

func TestSpcovHasBearerSubjectConfirmationNilSubject(t *testing.T) {
	assert.Assert(t, !hasBearerSubjectConfirmation(nil))
	assert.Assert(t, !hasBearerSubjectConfirmation(&Subject{}))
}

func TestSpcovValidateRequestID(t *testing.T) {
	e := spcovSetup(t)
	resp := Response{InResponseTo: "id-x"}

	assert.Error(t, e.sp.validateRequestID(resp, []string{"id-y"}),
		"`InResponseTo` does not match any of the possible request IDs (expected [id-y])")
	assert.NilError(t, e.sp.validateRequestID(resp, []string{"id-y", "id-x"}))

	e.sp.AllowIDPInitiated = true
	assert.NilError(t, e.sp.validateRequestID(resp, nil))
	e.sp.AllowIDPInitiated = false

	sentinel := errors.New("custom request id check")
	var gotIDs []string
	e.sp.ValidateRequestID = func(r Response, ids []string) error {
		assert.Equal(t, "id-x", r.InResponseTo)
		gotIDs = ids
		return sentinel
	}
	assert.Assert(t, errors.Is(e.sp.validateRequestID(resp, []string{"id-x"}), sentinel))
	assert.DeepEqual(t, []string{"id-x"}, gotIDs)
}

func TestSpcovFindChildren(t *testing.T) {
	root := spcovParse(t, `<r xmlns:a="urn:a" xmlns:b="urn:b"><a:x/><b:x/><a:x/><a:y/><x/></r>`)

	children, err := findChildren(root, "urn:a", "x")
	assert.NilError(t, err)
	assert.Equal(t, 2, len(children))

	// same local name, different namespace, is skipped
	children, err = findChildren(root, "urn:b", "x")
	assert.NilError(t, err)
	assert.Equal(t, 1, len(children))
	assert.Equal(t, "b", children[0].Space)

	_, err = findOneChild(root, "urn:a", "x")
	assert.Error(t, err, "expected exactly one urn:a:x element")
	_, err = findChild(root, "urn:a", "x")
	assert.Error(t, err, "expected at most one urn:a:x element")

	_, err = findOneChild(root, "urn:a", "z")
	assert.Error(t, err, "cannot find urn:a:z element")
	el, err := findChild(root, "urn:a", "z")
	assert.NilError(t, err)
	assert.Check(t, is.Nil(el))

	el, err = findOneChild(root, "urn:a", "y")
	assert.NilError(t, err)
	assert.Equal(t, "y", el.Tag)

	// undeclared prefix
	root = spcovParse(t, `<r><q:x/></r>`)
	_, err = findChildren(root, "urn:a", "x")
	assert.Error(t, err, "[urn:a]:x cannot find prefix q: undeclared namespace prefix: 'q'")
	_, err = findOneChild(root, "urn:a", "x")
	assert.Error(t, err, "[urn:a]:x cannot find prefix q: undeclared namespace prefix: 'q'")
	_, err = findChild(root, "urn:a", "x")
	assert.Error(t, err, "[urn:a]:x cannot find prefix q: undeclared namespace prefix: 'q'")

	// invalid namespace declaration on the parent
	root = spcovParse(t, `<r xmlns:xml="urn:not-xml"><x/></r>`)
	_, err = findChildren(root, "", "x")
	assert.Assert(t, errors.Is(err, etreeutils.ErrReservedNamespace), err)

	// invalid namespace declaration on the child itself
	root = spcovParse(t, `<r><x xmlns:xml="urn:not-xml"/></r>`)
	_, err = findChildren(root, "", "x")
	assert.Assert(t, errors.Is(err, etreeutils.ErrReservedNamespace), err)
}

func TestSpcovElementToStringAndUnmarshal(t *testing.T) {
	el := spcovParse(t, `<a:r xmlns:a="urn:a"><a:x>1</a:x></a:r>`)
	child := el.ChildElements()[0]
	s := elementToString(child)
	assert.Assert(t, strings.Contains(s, `xmlns:a="urn:a"`), s)

	var v struct {
		Value string `xml:",chardata"`
	}
	assert.NilError(t, unmarshalElement(child, &v))
	assert.Equal(t, "1", v.Value)

	var n struct {
		N int `xml:",chardata"`
	}
	bad := spcovParse(t, `<x>nope</x>`)
	assert.Error(t, unmarshalElement(bad, &n), `strconv.ParseInt: parsing "nope": invalid syntax`)
}
