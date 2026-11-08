package slo_test

import (
	"bytes"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/crewjam/saml/x/samlsp/slo"
)

// IsRequest and IsResponse do not parse a multipart body, which
// r.FormValue would, spooling its files to disk; package saml reads logout
// messages only from the query or an urlencoded body.
func TestIsRequestIgnoresMultipart(t *testing.T) {
	for _, field := range []string{"SAMLRequest", "SAMLResponse"} {
		var body bytes.Buffer
		mw := multipart.NewWriter(&body)
		if err := mw.WriteField(field, "x"); err != nil {
			t.Fatal(err)
		}
		fw, err := mw.CreateFormFile("upload", "big.bin")
		if err != nil {
			t.Fatal(err)
		}
		if _, err := fw.Write(bytes.Repeat([]byte("x"), 1<<16)); err != nil {
			t.Fatal(err)
		}
		if err := mw.Close(); err != nil {
			t.Fatal(err)
		}
		r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/slo", &body)
		r.Header.Set("Content-Type", mw.FormDataContentType())
		if slo.IsRequest(r) || slo.IsResponse(r) {
			t.Errorf("a multipart %s was taken for a logout message", field)
		}
		if r.MultipartForm != nil {
			t.Errorf("the multipart body with %s was parsed", field)
		}
	}

	post := func(field string) *http.Request {
		r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/slo", strings.NewReader(url.Values{field: {"x"}}.Encode()))
		r.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		return r
	}
	get := func(field string) *http.Request {
		return httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/slo?"+url.Values{field: {"x"}}.Encode(), nil)
	}
	for _, tt := range []struct {
		name     string
		r        *http.Request
		req, res bool
	}{
		{"POST SAMLRequest", post("SAMLRequest"), true, false},
		{"POST SAMLResponse", post("SAMLResponse"), false, true},
		{"GET SAMLRequest", get("SAMLRequest"), true, false},
		{"GET SAMLResponse", get("SAMLResponse"), false, true},
	} {
		if got := slo.IsRequest(tt.r); got != tt.req {
			t.Errorf("%s: IsRequest = %v", tt.name, got)
		}
		if got := slo.IsResponse(tt.r); got != tt.res {
			t.Errorf("%s: IsResponse = %v", tt.name, got)
		}
	}
}
