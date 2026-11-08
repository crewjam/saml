package samlsp_test

import (
	"bytes"
	"compress/flate"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml/x/samlsp"
)

const (
	peekIDP          = "https://idp.example.com/metadata"
	logoutRequestXML = `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol" xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion" ID="id-1" Version="2.0" IssueInstant="2026-01-01T00:00:00Z"><saml:Issuer> ` + peekIDP + ` </saml:Issuer><saml:NameID>alice</saml:NameID></samlp:LogoutRequest>`
)

func deflated(t *testing.T, s string) string {
	t.Helper()
	var buf bytes.Buffer
	w, err := flate.NewWriter(&buf, flate.BestCompression)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := io.WriteString(w, s); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return base64.StdEncoding.EncodeToString(buf.Bytes())
}

func redirectRequest(param, value string) *http.Request {
	return httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/slo?"+url.Values{param: {value}}.Encode(), nil)
}

func soapRequest(body string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/slo", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml; charset=utf-8")
	return r
}

// PeekUnverifiedIssuer names the IdP of a real Response, which then still verifies
// against that IdP.
func TestPeekUnverifiedIssuerResponse(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfigWithIDP(t, ti, nil)
	msg, err := cfg.AuthnRequest(t.Context(), "s", samlsp.WithIdentityProvider(staticIDP(ti)))
	if err != nil {
		t.Fatal(err)
	}
	acs := login(t, ti, msg)

	issuer, err := samlsp.PeekUnverifiedIssuer(acs)
	if err != nil {
		t.Fatal(err)
	}
	if want := ti.idp.Metadata().EntityID; issuer != want {
		t.Fatalf("PeekUnverifiedIssuer = %q, want %q", issuer, want)
	}
	if _, err := cfg.ParseResponse(t.Context(), acs, samlsp.WithRequestID(msg.ID), samlsp.WithIdentityProvider(staticIDP(ti))); err != nil {
		t.Fatalf("ParseResponse after PeekUnverifiedIssuer: %v", err)
	}
}

func TestPeekUnverifiedIssuerBindings(t *testing.T) {
	soapEnvelope := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` + logoutRequestXML + `</soap:Body></soap:Envelope>`
	for name, r := range map[string]*http.Request{
		"HTTP-Redirect LogoutRequest": redirectRequest("SAMLRequest", deflated(t, logoutRequestXML)),
		"HTTP-Redirect LogoutResponse": redirectRequest("SAMLResponse", deflated(t,
			`<samlp:LogoutResponse xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">`+peekIDP+`</Issuer></samlp:LogoutResponse>`)),
		"HTTP-POST LogoutRequest": postForm("https://sp.example.com/saml/slo", url.Values{
			"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(logoutRequestXML))},
		}),
		"HTTP-POST-SimpleSign LogoutRequest": postForm("https://sp.example.com/saml/slo", url.Values{
			"SAMLRequest": {base64.StdEncoding.EncodeToString([]byte(logoutRequestXML))},
			"SigAlg":      {"http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"}, "Signature": {"c2ln"},
		}),
		// A Response whose own Issuer is left out: its assertion's.
		"Response without its own Issuer": postForm(spACSURL, url.Values{
			"SAMLResponse": {base64.StdEncoding.EncodeToString([]byte(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"><saml:Assertion xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><saml:Issuer>` + peekIDP + `</saml:Issuer></saml:Assertion></samlp:Response>`))},
		}),
		"SOAP LogoutRequest": soapRequest(soapEnvelope),
	} {
		t.Run(name, func(t *testing.T) {
			issuer, err := samlsp.PeekUnverifiedIssuer(r)
			if err != nil {
				t.Fatal(err)
			}
			if issuer != peekIDP {
				t.Errorf("PeekUnverifiedIssuer = %q, want %q", issuer, peekIDP)
			}
		})
	}
}

// The SOAP body is put back, so that the message can then be verified.
func TestPeekUnverifiedIssuerSOAPBodyRestored(t *testing.T) {
	body := `<soap:Envelope xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/"><soap:Body>` + logoutRequestXML + `</soap:Body></soap:Envelope>`
	r := soapRequest(body)
	if _, err := samlsp.PeekUnverifiedIssuer(r); err != nil {
		t.Fatal(err)
	}
	got, err := io.ReadAll(r.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != body {
		t.Errorf("body after PeekUnverifiedIssuer = %q", got)
	}
}

func TestPeekUnverifiedIssuerRefused(t *testing.T) {
	b64 := func(s string) string { return base64.StdEncoding.EncodeToString([]byte(s)) }
	post := func(v url.Values) *http.Request { return postForm(spACSURL, v) }
	huge := deflated(t, `<samlp:LogoutRequest xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol">`+strings.Repeat(" ", 2<<20)+`</samlp:LogoutRequest>`)
	queryOnly := httptest.NewRequest(http.MethodPost, spACSURL+"?"+url.Values{"SAMLResponse": {b64(logoutRequestXML)}}.Encode(), nil)

	for _, tt := range []struct {
		name       string
		r          *http.Request
		noIssuerIs bool // the error matches ErrNoIssuer
	}{
		{"no message", post(url.Values{}), true},
		{"HTTP-Artifact", redirectRequest("SAMLart", "AAQAAA=="), true},
		{"POST message in the query string", queryOnly, true},
		{"no Issuer", post(url.Values{"SAMLResponse": {b64(`<samlp:Response xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"/>`)}}), true},
		{"PUT", httptest.NewRequest(http.MethodPut, spACSURL, nil), true},
		{"both a request and a response", post(url.Values{"SAMLRequest": {b64(logoutRequestXML)}, "SAMLResponse": {b64(logoutRequestXML)}}), false},
		{"not base64", post(url.Values{"SAMLResponse": {"!!!"}}), false},
		{"not XML", post(url.Values{"SAMLResponse": {b64("not XML")}}), false},
		{"not a protocol message", post(url.Values{"SAMLResponse": {b64(`<md:EntityDescriptor xmlns:md="urn:oasis:names:tc:SAML:2.0:metadata"><Issuer xmlns="urn:oasis:names:tc:SAML:2.0:assertion">x</Issuer></md:EntityDescriptor>`)}}), false},
		{"Redirect not deflated", redirectRequest("SAMLRequest", b64(logoutRequestXML)), false},
		{"Redirect inflating too far", redirectRequest("SAMLRequest", huge), false},
		{"SOAP, not an Envelope", soapRequest(logoutRequestXML), false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			issuer, err := samlsp.PeekUnverifiedIssuer(tt.r)
			if err == nil {
				t.Fatalf("PeekUnverifiedIssuer = %q, want an error", issuer)
			}
			if errors.Is(err, samlsp.ErrNoIssuer) != tt.noIssuerIs {
				t.Errorf("err = %v; matches ErrNoIssuer: %v, want %v", err, !tt.noIssuerIs, tt.noIssuerIs)
			}
		})
	}
}
