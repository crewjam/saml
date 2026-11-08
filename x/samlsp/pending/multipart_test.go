package pending_test

import (
	"bytes"
	"errors"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/crewjam/saml/x/samlsp/pending"
)

// multipartRequest returns a multipart POST to the ACS with a RelayState
// field and a file, as an attacker could send unauthenticated.
func multipartRequest(t *testing.T, relayState string) *http.Request {
	t.Helper()
	var body bytes.Buffer
	mw := multipart.NewWriter(&body)
	if err := mw.WriteField("RelayState", relayState); err != nil {
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
	r := httptest.NewRequest(http.MethodPost, "https://sp.example.com/saml/acs", &body)
	r.Header.Set("Content-Type", mw.FormDataContentType())
	return r
}

// Find reads the RelayState as ParseResponse does: not from a multipart
// body, which r.FormValue would parse, spooling its files to disk.
func TestFindIgnoresMultipart(t *testing.T) {
	cfg, _ := newConfig(t)
	tr := newTracker(t, cfg)
	_, w := remember(t, cfg, tr, "state-1", "/next")
	browser := jar{}
	browser.set(w)

	r := multipartRequest(t, "state-1")
	for _, c := range browser {
		r.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: a request cookie carries no attributes
	}
	if _, err := tr.Find(httptest.NewRecorder(), r); !errors.Is(err, pending.ErrNotFound) {
		t.Errorf("Find with a multipart body: %v, want ErrNotFound", err)
	}
	if r.MultipartForm != nil {
		t.Error("Find parsed the multipart body")
	}

	// The urlencoded POST of the HTTP-POST binding, and the query of an
	// HTTP-Artifact redirect, are read.
	if _, err := tr.Find(httptest.NewRecorder(), browser.request("state-1")); err != nil {
		t.Errorf("Find with an urlencoded body: %v", err)
	}
	get := httptest.NewRequest(http.MethodGet, "https://sp.example.com/saml/acs?SAMLart=x&RelayState=state-1", nil)
	for _, c := range browser {
		get.AddCookie(&http.Cookie{Name: c.Name, Value: c.Value}) //nolint:gosec // G124: a request cookie carries no attributes
	}
	if _, err := tr.Find(httptest.NewRecorder(), get); err != nil {
		t.Errorf("Find with a query: %v", err)
	}
}
