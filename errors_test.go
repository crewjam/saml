package saml

import (
	"bytes"
	"crypto/x509"
	"encoding/base64"
	"encoding/xml"
	"errors"
	"log"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
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
	ErrUnknownServiceProvider, ErrUnknownAssertionConsumerService, ErrUnsupported,
	ErrInvalidCertificate, ErrAuthnContextMismatch,
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
		{"response Destination", func(r *Response, _ *Assertion) { r.Destination = "https://elsewhere.example.com/acs" }, ErrDestinationMismatch},
		{"response IssueInstant", func(r *Response, _ *Assertion) { r.IssueInstant = old }, ErrExpired},
		{"response Issuer", func(r *Response, _ *Assertion) { r.Issuer.Value = "https://other-idp.example.com" }, ErrIssuerMismatch},
		{"response InResponseTo", func(r *Response, _ *Assertion) { r.InResponseTo = "id-other" }, ErrRequestIDMismatch},
		{"no Assertion", func(r *Response, _ *Assertion) { r.Assertion = nil }, ErrMissingElement},
		{"assertion Subject", func(_ *Response, a *Assertion) { a.Subject = nil }, ErrMissingElement},
		{"assertion Conditions", func(_ *Response, a *Assertion) { a.Conditions = nil }, ErrMissingElement},
		{"assertion bearer", func(_ *Response, a *Assertion) { a.Subject.SubjectConfirmations[0].Method = "urn:other" }, ErrMissingElement},
		{"assertion IssueInstant", func(_ *Response, a *Assertion) { a.IssueInstant = old }, ErrExpired},
		{"assertion SubjectConfirmationData NotOnOrAfter", func(_ *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotOnOrAfter = old
		}, ErrExpired},
		{"assertion Conditions NotOnOrAfter", func(_ *Response, a *Assertion) { a.Conditions.NotOnOrAfter = old }, ErrExpired},
		{"assertion Conditions NotBefore", func(_ *Response, a *Assertion) { a.Conditions.NotBefore = future }, ErrNotYetValid},
		{"assertion SubjectConfirmationData NotBefore", func(_ *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.NotBefore = future
		}, ErrNotYetValid},
		{"assertion Issuer", func(_ *Response, a *Assertion) { a.Issuer.Value = "https://other-idp.example.com" }, ErrIssuerMismatch},
		{"assertion Recipient", func(_ *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.Recipient = "https://elsewhere.example.com/acs"
		}, ErrDestinationMismatch},
		{"assertion InResponseTo", func(_ *Response, a *Assertion) {
			a.Subject.SubjectConfirmations[0].SubjectConfirmationData.InResponseTo = "id-other"
		}, ErrRequestIDMismatch},
		{"assertion audience", func(_ *Response, a *Assertion) {
			a.Conditions.AudienceRestrictions[0].Audience.Value = "https://other-sp.example.com"
		}, ErrAudienceMismatch},
		{"assertion no AudienceRestriction", func(_ *Response, a *Assertion) { a.Conditions.AudienceRestrictions = nil }, ErrAudienceMismatch},
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

	t.Run("AuthnContextClassRef", func(t *testing.T) {
		password := "urn:oasis:names:tc:SAML:2.0:ac:classes:Password" //nolint:gosec // an AuthnContextClassRef URI, not a credential
		mfa := "https://refeds.org/profile/mfa"
		r := e.response()
		r.Assertion = e.assertion()
		r.Assertion.AuthnStatements = []AuthnStatement{{
			AuthnInstant: spcovNow,
			AuthnContext: AuthnContext{AuthnContextClassRef: &AuthnContextClassRef{Value: password}},
		}}
		buf := spcovSerialize(t, e.idpSign(t, r.Element()))

		sp := *e.sp
		sp.ValidateAuthnContextClassRef = true
		sp.RequestedAuthnContext = &RequestedAuthnContext{AuthnContextClassRefs: []string{mfa}}
		_, err := sp.ParseXMLResponse(buf, []string{spcovRequestID}, sp.AcsURL)
		checkOnlyKind(t, err, ErrAuthnContextMismatch)

		sp.RequestedAuthnContext = &RequestedAuthnContext{Comparison: "minimum", AuthnContextClassRefs: []string{password}}
		_, err = sp.ParseXMLResponse(buf, []string{spcovRequestID}, sp.AcsURL)
		checkOnlyKind(t, err, ErrUnsupported)
	})

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

func TestIdpAuthnRequestErrorKinds(t *testing.T) {
	test := idpcovNewTest(t)

	validate := func(t *testing.T, mutate func(r *AuthnRequest)) error {
		t.Helper()
		authnRequest, err := test.SP.MakeAuthenticationRequest(test.SP.GetSSOBindingLocation(HTTPRedirectBinding), HTTPRedirectBinding, HTTPPostBinding)
		assert.NilError(t, err)
		mutate(authnRequest)
		buf, err := xml.Marshal(authnRequest)
		assert.NilError(t, err)
		req := IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), RequestBuffer: buf,
			HTTPRequest: httptest.NewRequest("POST", "https://idp.example.com/saml/sso", nil)}
		return req.Validate()
	}
	assert.NilError(t, validate(t, func(*AuthnRequest) {}))

	tests := []struct {
		name   string
		mutate func(r *AuthnRequest)
		want   error
	}{
		{"Destination", func(r *AuthnRequest) { r.Destination = "https://elsewhere.example.com/sso" }, ErrDestinationMismatch},
		{"IssueInstant", func(r *AuthnRequest) { r.IssueInstant = TimeNow().Add(-time.Hour) }, ErrExpired},
		{"Version", func(r *AuthnRequest) { r.Version = "1.1" }, ErrUnsupported},
		{"no Issuer", func(r *AuthnRequest) { r.Issuer = nil }, ErrMissingElement},
		{"unknown Issuer", func(r *AuthnRequest) { r.Issuer.Value = "https://other-sp.example.com/metadata" }, ErrUnknownServiceProvider},
		{"unknown AssertionConsumerServiceURL", func(r *AuthnRequest) {
			r.AssertionConsumerServiceURL = "https://sp.example.com/elsewhere"
		}, ErrUnknownAssertionConsumerService},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkOnlyKind(t, validate(t, tc.mutate), tc.want)
		})
	}

	t.Run("unknown Issuer matches os.ErrNotExist", func(t *testing.T) {
		err := validate(t, func(r *AuthnRequest) { r.Issuer.Value = "https://other-sp.example.com/metadata" })
		assert.Check(t, errors.Is(err, os.ErrNotExist))
	})

	t.Run("invalid XML", func(t *testing.T) {
		req := IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), RequestBuffer: []byte("<a>")}
		checkOnlyKind(t, req.Validate(), ErrMalformedMessage)
	})

	t.Run("wrong root element", func(t *testing.T) {
		req := IdpAuthnRequest{IDP: &test.IDP, Now: TimeNow(), RequestBuffer: []byte("<NotAnAuthnRequest/>")}
		checkOnlyKind(t, req.Validate(), ErrMalformedMessage)
	})

	t.Run("service provider lookup error is wrapped", func(t *testing.T) {
		lookupErr := errors.New("database on fire")
		old := test.IDP.ServiceProviderProvider
		t.Cleanup(func() { test.IDP.ServiceProviderProvider = old })
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return nil, lookupErr },
		}
		err := validate(t, func(*AuthnRequest) {})
		checkOnlyKind(t, err, nil)
		assert.Check(t, errors.Is(err, lookupErr))
	})

	t.Run("NewIdpAuthnRequest", func(t *testing.T) {
		tests := []struct {
			name string
			r    *http.Request
			want error
		}{
			{"GET bad base64", httptest.NewRequest("GET", "https://idp.example.com/saml/sso?SAMLRequest=%21%21", nil), ErrMalformedMessage},
			{"GET bad deflate", httptest.NewRequest("GET", "https://idp.example.com/saml/sso?SAMLRequest=AAAA", nil), ErrMalformedMessage},
			{"POST bad base64", func() *http.Request {
				r := httptest.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader("SAMLRequest=%21%21"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(), ErrMalformedMessage},
			{"POST bad form", func() *http.Request {
				r := httptest.NewRequest("POST", "https://idp.example.com/saml/sso", strings.NewReader("SAMLRequest=%zz"))
				r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
				return r
			}(), ErrMalformedMessage},
			{"PUT", httptest.NewRequest("PUT", "https://idp.example.com/saml/sso", nil), ErrUnsupported},
		}
		for _, tc := range tests {
			t.Run(tc.name, func(t *testing.T) {
				_, err := NewIdpAuthnRequest(&test.IDP, tc.r)
				checkOnlyKind(t, err, tc.want)
			})
		}
	})

	t.Run("PostBinding unsupported binding", func(t *testing.T) {
		req := idpcovRequest(t, test)
		req.ResponseEl = etree.NewElement("Response")
		req.ACSEndpoint.Binding = HTTPRedirectBinding
		_, err := req.PostBinding()
		checkOnlyKind(t, err, ErrUnsupported)
	})
}

func TestNewIdpInitiatedRequestErrorKinds(t *testing.T) {
	test := idpcovNewTest(t)
	r := httptest.NewRequest("GET", "https://idp.example.com/saml/idp-initiated", nil)
	spID := test.SP.MetadataURL.String()

	req, err := test.IDP.NewIdpInitiatedRequest(r, spID, "relay")
	assert.NilError(t, err)
	assert.Equal(t, HTTPPostBinding, req.ACSEndpoint.Binding)
	assert.Equal(t, "relay", req.RelayState)
	assert.Equal(t, spID, req.ServiceProviderMetadata.EntityID)

	t.Run("unknown service provider", func(t *testing.T) {
		_, err := test.IDP.NewIdpInitiatedRequest(r, "https://other-sp.example.com/metadata", "")
		assert.Error(t, err, "cannot find service provider: https://other-sp.example.com/metadata")
		checkOnlyKind(t, err, ErrUnknownServiceProvider)
		assert.Check(t, errors.Is(err, os.ErrNotExist))
	})

	withProvider := func(t *testing.T, f func(*http.Request, string) (*EntityDescriptor, error)) {
		old := test.IDP.ServiceProviderProvider
		t.Cleanup(func() { test.IDP.ServiceProviderProvider = old })
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{GetServiceProviderFunc: f}
	}

	t.Run("no HTTP-POST assertion consumer service", func(t *testing.T) {
		withProvider(t, func(*http.Request, string) (*EntityDescriptor, error) {
			return &EntityDescriptor{EntityID: spID, SPSSODescriptors: []SPSSODescriptor{{
				AssertionConsumerServices: []IndexedEndpoint{{Binding: HTTPRedirectBinding, Location: "https://sp.example.com/acs"}},
			}}}, nil
		})
		_, err := test.IDP.NewIdpInitiatedRequest(r, spID, "")
		assert.Error(t, err, "saml metadata does not contain an Assertion Customer Service url")
		checkOnlyKind(t, err, ErrUnknownAssertionConsumerService)
	})

	t.Run("service provider lookup error is wrapped", func(t *testing.T) {
		lookupErr := errors.New("database on fire")
		withProvider(t, func(*http.Request, string) (*EntityDescriptor, error) { return nil, lookupErr })
		_, err := test.IDP.NewIdpInitiatedRequest(r, spID, "")
		checkOnlyKind(t, err, nil)
		assert.Check(t, errors.Is(err, lookupErr))
	})
}

func TestInvalidCertificateErrorKinds(t *testing.T) {
	t.Run("IdP: SP encryption certificate", func(t *testing.T) {
		test := idpcovNewTest(t)
		for _, data := range []string{"!!!", base64.StdEncoding.EncodeToString([]byte("not a certificate"))} {
			req := idpcovMadeAssertion(t, test)
			req.SPSSODescriptor.KeyDescriptors = []KeyDescriptor{idpcovCertKeyDescriptor("encryption", data)}
			_, err := req.getSPEncryptionCert()
			checkOnlyKind(t, err, ErrInvalidCertificate)
			checkOnlyKind(t, req.MakeAssertionEl(), ErrInvalidCertificate)
		}
	})

	e := spcovSetup(t)
	notACert := base64.StdEncoding.EncodeToString([]byte("not a certificate"))
	tests := []struct {
		name   string
		mutate func(sp *ServiceProvider)
	}{
		{"SP: IdP metadata certificate base64", func(sp *ServiceProvider) {
			sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data = "!!!"
		}},
		{"SP: IdP metadata certificate", func(sp *ServiceProvider) {
			sp.IDPMetadata.IDPSSODescriptors[0].KeyDescriptors[0].KeyInfo.X509Data.X509Certificates[0].Data = notACert
		}},
		{"SP: IDPCertificate", func(sp *ServiceProvider) { sp.IDPCertificate = &notACert }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			sp := *e.sp
			sp.IDPMetadata = spcovIDPMetadata(e.idpCert)
			tc.mutate(&sp)
			_, err := sp.ParseXMLResponse(e.signedResponse(t), []string{spcovRequestID}, sp.AcsURL)
			assert.Check(t, errors.Is(err, ErrInvalidCertificate))
			assert.Check(t, errors.Is(err, ErrInvalidSignature))
			assert.Check(t, !errors.Is(err, ErrUntrustedCertificate))
		})
	}
}

func TestIdentityProviderOnError(t *testing.T) {
	type call struct {
		status int
		err    error
	}
	setup := func(t *testing.T) (*IdentityProviderTest, *[]call) {
		test := idpcovNewTest(t)
		test.IDP.SessionProvider = &mockSessionProvider{GetSessionFunc: idpcovAliceSession}
		var calls []call
		test.IDP.OnError = func(w http.ResponseWriter, _ *http.Request, status int, err error) {
			calls = append(calls, call{status, err})
			w.WriteHeader(http.StatusTeapot)
		}
		return test, &calls
	}
	spMetadata := func(test *IdentityProviderTest, mutate func(*EntityDescriptor)) {
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(_ *http.Request, id string) (*EntityDescriptor, error) {
				if id != test.SP.MetadataURL.String() {
					return nil, os.ErrNotExist
				}
				md := test.SP.Metadata()
				mutate(md)
				return md, nil
			},
		}
	}
	badEncryptionCert := func(md *EntityDescriptor) {
		md.SPSSODescriptors[0].KeyDescriptors = []KeyDescriptor{idpcovCertKeyDescriptor("encryption", "!!!")}
	}

	t.Run("ServeSSO unparseable request", func(t *testing.T) {
		test, calls := setup(t)
		w := httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest("PUT", "https://idp.example.com/saml/sso", nil))
		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusBadRequest, (*calls)[0].status)
		assert.Error(t, (*calls)[0].err, "failed to parse request: method not allowed")
		assert.Check(t, errors.Is((*calls)[0].err, ErrUnsupported))
	})

	t.Run("ServeSSO invalid request", func(t *testing.T) {
		test, calls := setup(t)
		r := idpcovSSORequest(t, test)
		test.IDP.ServiceProviderProvider = &mockServiceProviderProvider{
			GetServiceProviderFunc: func(*http.Request, string) (*EntityDescriptor, error) { return nil, os.ErrNotExist },
		}
		test.IDP.ServeSSO(httptest.NewRecorder(), r)
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusBadRequest, (*calls)[0].status)
		assert.Check(t, errors.Is((*calls)[0].err, ErrUnknownServiceProvider))
	})

	t.Run("ServeSSO bad SP encryption certificate", func(t *testing.T) {
		test, calls := setup(t)
		spMetadata(test, badEncryptionCert)
		test.IDP.ServeSSO(httptest.NewRecorder(), idpcovSSORequest(t, test))
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusInternalServerError, (*calls)[0].status)
		assert.Check(t, errors.Is((*calls)[0].err, ErrInvalidCertificate))
	})

	t.Run("ServeSSO assertion maker error", func(t *testing.T) {
		test, calls := setup(t)
		makerErr := errors.New("no assertion for you")
		test.IDP.AssertionMaker = idpcovAssertionMakerFunc(func(*IdpAuthnRequest, *Session) error { return makerErr })
		test.IDP.ServeSSO(httptest.NewRecorder(), idpcovSSORequest(t, test))
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusInternalServerError, (*calls)[0].status)
		assert.Error(t, (*calls)[0].err, "failed to make assertion: no assertion for you")
		assert.Check(t, errors.Is((*calls)[0].err, makerErr))
	})

	t.Run("ServeIDPInitiated unknown service provider", func(t *testing.T) {
		test, calls := setup(t)
		test.IDP.ServeIDPInitiated(httptest.NewRecorder(), httptest.NewRequest("GET", "https://idp.example.com/", nil), "https://other-sp.example.com/metadata", "")
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusNotFound, (*calls)[0].status)
		assert.Check(t, errors.Is((*calls)[0].err, ErrUnknownServiceProvider))
	})

	t.Run("ServeIDPInitiated bad SP encryption certificate", func(t *testing.T) {
		test, calls := setup(t)
		spMetadata(test, badEncryptionCert)
		test.IDP.ServeIDPInitiated(httptest.NewRecorder(), httptest.NewRequest("GET", "https://idp.example.com/", nil), test.SP.MetadataURL.String(), "")
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusInternalServerError, (*calls)[0].status)
		assert.Check(t, errors.Is((*calls)[0].err, ErrInvalidCertificate))
	})

	t.Run("OnError can delegate to DefaultOnError", func(t *testing.T) {
		test, _ := setup(t)
		var logged bytes.Buffer
		test.IDP.Logger = log.New(&logged, "", 0)
		test.IDP.OnError = func(w http.ResponseWriter, r *http.Request, status int, err error) {
			if errors.Is(err, ErrUnknownServiceProvider) {
				w.WriteHeader(http.StatusTeapot)
				return
			}
			test.IDP.DefaultOnError(w, r, status, err)
		}

		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest("GET", "https://idp.example.com/", nil), "https://other-sp.example.com/metadata", "")
		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Equal(t, "", logged.String())

		w = httptest.NewRecorder()
		test.IDP.ServeSSO(w, httptest.NewRequest("PUT", "https://idp.example.com/saml/sso", nil))
		assert.Equal(t, http.StatusBadRequest, w.Code)
		assert.Equal(t, "failed to parse request: method not allowed\n", logged.String())
	})

	t.Run("ServeMetadata signing error", func(t *testing.T) {
		test, calls := setup(t)
		test.IDP.SignMetadata = true
		test.IDP.Signer = idpcovFailingSigner{Signer: mustParsePrivateKey(golden.Get(t, "idp_key.pem"))}
		w := httptest.NewRecorder()
		test.IDP.ServeMetadata(w, httptest.NewRequest("GET", "https://idp.example.com/saml/metadata", nil))
		assert.Equal(t, http.StatusTeapot, w.Code)
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusInternalServerError, (*calls)[0].status)
		assert.ErrorContains(t, (*calls)[0].err, "failed to sign metadata: ")
		assert.ErrorContains(t, (*calls)[0].err, "idpcov: sign failed")
	})

	t.Run("ServeMetadata write error", func(t *testing.T) {
		test, calls := setup(t)
		test.IDP.ServeMetadata(&idpcovFailingResponseWriter{}, httptest.NewRequest("GET", "https://idp.example.com/saml/metadata", nil))
		assert.Assert(t, len(*calls) == 1)
		assert.Equal(t, http.StatusInternalServerError, (*calls)[0].status)
		assert.ErrorContains(t, (*calls)[0].err, "failed to write metadata: ")
	})

	t.Run("ServeMetadata without OnError", func(t *testing.T) {
		test, _ := setup(t)
		test.IDP.OnError = nil
		var logged bytes.Buffer
		test.IDP.Logger = log.New(&logged, "", 0)
		w := &idpcovFailingResponseWriter{}
		test.IDP.ServeMetadata(w, httptest.NewRequest("GET", "https://idp.example.com/saml/metadata", nil))
		assert.Equal(t, http.StatusInternalServerError, w.code)
		assert.Check(t, strings.HasPrefix(logged.String(), "failed to write metadata: "), logged.String())
	})

	t.Run("without OnError the log line and status are unchanged", func(t *testing.T) {
		test, _ := setup(t)
		test.IDP.OnError = nil
		var logged bytes.Buffer
		test.IDP.Logger = log.New(&logged, "", 0)
		w := httptest.NewRecorder()
		test.IDP.ServeIDPInitiated(w, httptest.NewRequest("GET", "https://idp.example.com/", nil), "https://other-sp.example.com/metadata", "")
		assert.Equal(t, http.StatusNotFound, w.Code)
		assert.Equal(t, "cannot find service provider: https://other-sp.example.com/metadata\n", logged.String())
	})
}
