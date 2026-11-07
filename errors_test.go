package saml

import (
	"crypto/x509"
	"encoding/base64"
	"errors"
	"testing"
	"time"

	"github.com/beevik/etree"
	"gotest.tools/v3/assert"
	"gotest.tools/v3/golden"
)

func TestClassify(t *testing.T) {
	assert.NilError(t, classify(nil, ErrInvalidSignature))

	inner := errors.New("inner")
	err := classify(inner, ErrInvalidSignature, ErrUntrustedCertificate)
	assert.Error(t, err, "inner")
	assert.Check(t, errors.Is(err, inner))
	assert.Check(t, errors.Is(err, ErrInvalidSignature))
	assert.Check(t, errors.Is(err, ErrUntrustedCertificate))
	assert.Check(t, !errors.Is(err, ErrCertificateNotValidNow))

	// InvalidResponseError exposes PrivateErr to errors.Is and errors.As
	wrapped := &InvalidResponseError{PrivateErr: ErrBadStatus{Status: "urn:oasis:names:tc:SAML:2.0:status:Requester"}}
	var badStatus ErrBadStatus
	assert.Check(t, errors.As(wrapped, &badStatus))
	assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Requester", badStatus.Status)
}

func TestClassifyCertificate(t *testing.T) {
	idpCert := mustParseCertificate(golden.Get(t, "idp_cert.pem"))
	otherCert := mustParseCertificate(golden.Get(t, "cert_2017.pem"))
	valid := idpCert.NotBefore.Add(time.Hour)

	signedWith := func(cert *x509.Certificate) *etree.Element {
		el := etree.NewElement("Response")
		x := el.CreateElement("Signature").CreateElement("KeyInfo").CreateElement("X509Data").CreateElement("X509Certificate")
		if cert != nil {
			x.SetText(base64.StdEncoding.EncodeToString(cert.Raw))
		} else {
			x.SetText("!!!")
		}
		return el
	}
	noKeyInfo := etree.NewElement("Response")
	noKeyInfo.CreateElement("Signature")
	keyInfoWithoutCert := etree.NewElement("Response")
	keyInfoWithoutCert.CreateElement("Signature").CreateElement("KeyInfo")

	tests := []struct {
		name  string
		el    *etree.Element
		roots []*x509.Certificate
		now   time.Time
		want  error
	}{
		{"trusted and valid", signedWith(idpCert), []*x509.Certificate{otherCert, idpCert}, valid, nil},
		{"untrusted", signedWith(otherCert), []*x509.Certificate{idpCert}, valid, ErrUntrustedCertificate},
		{"trusted but expired", signedWith(idpCert), []*x509.Certificate{idpCert}, idpCert.NotAfter.Add(time.Hour), ErrCertificateNotValidNow},
		{"trusted but not yet valid", signedWith(idpCert), []*x509.Certificate{idpCert}, idpCert.NotBefore.Add(-time.Hour), ErrCertificateNotValidNow},
		{"embedded certificate does not parse", signedWith(nil), []*x509.Certificate{idpCert}, valid, nil},
		{"no KeyInfo, one root", noKeyInfo, []*x509.Certificate{idpCert}, idpCert.NotAfter.Add(time.Hour), ErrCertificateNotValidNow},
		{"no KeyInfo, several roots", noKeyInfo, []*x509.Certificate{idpCert, otherCert}, valid, nil},
		{"KeyInfo without certificate", keyInfoWithoutCert, []*x509.Certificate{idpCert}, valid, nil},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			assert.Equal(t, tc.want, classifyCertificate(tc.el, tc.roots, tc.now))
		})
	}
}
