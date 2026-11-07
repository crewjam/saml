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

// allErrorKinds is every error value the ServiceProvider attaches to a
// rejection, so tests can check that exactly the expected one matches.
var allErrorKinds = []error{
	ErrInvalidSignature, ErrUntrustedCertificate, ErrCertificateNotValidNow,
	ErrMalformedMessage, ErrMissingElement, ErrExpired, ErrNotYetValid,
	ErrIssuerMismatch, ErrDestinationMismatch, ErrRequestIDMismatch,
	ErrAudienceMismatch, ErrDecryptionFailed, ErrArtifactResolution,
}

func checkOnlyKind(t *testing.T, err error, want error) {
	t.Helper()
	assert.Assert(t, err != nil)
	for _, kind := range allErrorKinds {
		assert.Check(t, errors.Is(err, kind) == (kind == want), "errors.Is(%q, %v)", err, kind)
	}
}

func TestParseXMLResponseErrorKinds(t *testing.T) {
	e := spcovSetup(t)
	old := spcovNow.Add(-time.Hour)
	future := spcovNow.Add(time.Hour)

	tests := []struct {
		name   string
		mutate func(r *Response, a *Assertion)
		want   error
	}{
		{"response Destination", func(r *Response, a *Assertion) { r.Destination = "https://elsewhere.example.com/acs" }, ErrDestinationMismatch},
		{"response IssueInstant", func(r *Response, a *Assertion) { r.IssueInstant = old }, ErrExpired},
		{"response Issuer", func(r *Response, a *Assertion) { r.Issuer.Value = "https://other-idp.example.com" }, ErrIssuerMismatch},
		{"response InResponseTo", func(r *Response, a *Assertion) { r.InResponseTo = "id-other" }, ErrRequestIDMismatch},
		{"no Assertion", func(r *Response, a *Assertion) { r.Assertion = nil }, ErrMissingElement},
		{"assertion Subject", func(r *Response, a *Assertion) { a.Subject = nil }, ErrMissingElement},
		{"assertion Conditions", func(r *Response, a *Assertion) { a.Conditions = nil }, ErrMissingElement},
		{"assertion bearer", func(r *Response, a *Assertion) { a.Subject.SubjectConfirmations[0].Method = "urn:other" }, ErrMissingElement},
		{"assertion IssueInstant", func(r *Response, a *Assertion) { a.IssueInstant = old }, ErrExpired},
		{"assertion SubjectConfirmationData NotOnOrAfter", func(r *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = old
		}, ErrExpired},
		{"assertion Conditions NotOnOrAfter", func(r *Response, a *Assertion) { a.Conditions.NotOnOrAfter = old }, ErrExpired},
		{"assertion Conditions NotBefore", func(r *Response, a *Assertion) { a.Conditions.NotBefore = future }, ErrNotYetValid},
		{"assertion Issuer", func(r *Response, a *Assertion) { a.Issuer.Value = "https://other-idp.example.com" }, ErrIssuerMismatch},
		{"assertion Recipient", func(r *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "https://elsewhere.example.com/acs"
		}, ErrDestinationMismatch},
		{"assertion InResponseTo", func(r *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "id-other"
		}, ErrRequestIDMismatch},
		{"assertion audience", func(r *Response, a *Assertion) {
			a.Conditions.AudienceRestrictions[0].Audience.Value = "https://other-sp.example.com"
		}, ErrAudienceMismatch},
		{"assertion no AudienceRestriction", func(r *Response, a *Assertion) { a.Conditions.AudienceRestrictions = nil }, ErrAudienceMismatch},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			r := e.response()
			r.Assertion = e.assertion()
			tc.mutate(r, r.Assertion)
			buf := spcovSerialize(t, e.idpSign(t, r.Element()))
			_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
			var ire *InvalidResponseError
			assert.Assert(t, errors.As(err, &ire))
			checkOnlyKind(t, err, tc.want)
		})
	}

	t.Run("invalid XML", func(t *testing.T) {
		_, err := e.sp.ParseXMLResponse([]byte("<a>"), []string{spcovRequestID}, e.sp.AcsURL)
		checkOnlyKind(t, err, ErrMalformedMessage)
	})

	t.Run("ValidateAudienceRestriction hook", func(t *testing.T) {
		sp := *e.sp
		hookErr := errors.New("not for us")
		sp.ValidateAudienceRestriction = func(*Assertion) error { return hookErr }
		_, err := sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, sp.AcsURL)
		checkOnlyKind(t, err, ErrAudienceMismatch)
		assert.Check(t, errors.Is(err, hookErr))
	})

	t.Run("EncryptedAssertion for another key", func(t *testing.T) {
		other := *e
		otherSP := *e.sp
		otherSP.Certificate = mustParseCertificate(golden.Get(t, "cert_2017.pem"))
		other.sp = &otherSP
		plaintext := spcovSerialize(t, e.assertion().Element())
		responseEl := e.response().Element()
		responseEl.AddChild(other.encryptedAssertion(t, plaintext))
		buf := spcovSerialize(t, e.idpSign(t, responseEl))
		_, err := e.sp.ParseXMLResponse(buf, []string{spcovRequestID}, e.sp.AcsURL)
		checkOnlyKind(t, err, ErrDecryptionFailed)
	})
}

func TestLogoutErrorKinds(t *testing.T) {
	e := spcovSetup(t)
	old := spcovNow.Add(-time.Hour)

	t.Run("LogoutResponse", func(t *testing.T) {
		tests := []struct {
			name   string
			mutate func(r *LogoutResponse)
			want   error
		}{
			{"Destination", func(r *LogoutResponse) { r.Destination = "https://elsewhere.example.com/slo" }, ErrDestinationMismatch},
			{"IssueInstant", func(r *LogoutResponse) { r.IssueInstant = old }, ErrExpired},
			{"Issuer", func(r *LogoutResponse) { r.Issuer = nil }, ErrIssuerMismatch},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := e.logoutResponse()
				tc.mutate(r)
				checkOnlyKind(t, e.sp.validateLogoutResponse(r), tc.want)
			})
		}

		t.Run("Status", func(t *testing.T) {
			r := e.logoutResponse()
			r.Status.StatusCode.Value = "urn:oasis:names:tc:SAML:2.0:status:Requester"
			err := e.sp.validateLogoutResponse(r)
			assert.Error(t, err, "status code was not "+StatusSuccess)
			var badStatus ErrBadStatus
			assert.Assert(t, errors.As(err, &badStatus))
			assert.Equal(t, "urn:oasis:names:tc:SAML:2.0:status:Requester", badStatus.Status)
		})
	})

	t.Run("LogoutRequest", func(t *testing.T) {
		request := func() *LogoutRequest {
			return &LogoutRequest{
				ID:           "id-logout-request",
				Version:      "2.0",
				IssueInstant: spcovNow,
				Destination:  e.sp.SloURL.String(),
				Issuer:       &Issuer{Value: spcovIDPEntityID},
				NameID:       &NameID{Value: "alice@example.com"},
			}
		}
		assert.NilError(t, e.sp.validateLogoutRequest(request()))

		tests := []struct {
			name   string
			mutate func(r *LogoutRequest)
			want   error
		}{
			{"Destination", func(r *LogoutRequest) { r.Destination = "https://elsewhere.example.com/slo" }, ErrDestinationMismatch},
			{"IssueInstant old", func(r *LogoutRequest) { r.IssueInstant = old }, ErrExpired},
			{"IssueInstant future", func(r *LogoutRequest) { r.IssueInstant = spcovNow.Add(time.Hour) }, ErrNotYetValid},
			{"NotOnOrAfter", func(r *LogoutRequest) { r.NotOnOrAfter = &old }, ErrExpired},
			{"Issuer", func(r *LogoutRequest) { r.Issuer.Value = "https://other-idp.example.com" }, ErrIssuerMismatch},
			{"NameID", func(r *LogoutRequest) { r.NameID = nil }, ErrMissingElement},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				r := request()
				tc.mutate(r)
				checkOnlyKind(t, e.sp.validateLogoutRequest(r), tc.want)
			})
		}
	})
}
