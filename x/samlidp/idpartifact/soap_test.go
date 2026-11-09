package idpartifact_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
)

const (
	soapStart = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>`
	soapEnd   = `</soapenv:Body></soapenv:Envelope>`
)

// artifact returns the artifact of a Response to an AuthnRequest of SP 1.
func (w *world) artifact(t *testing.T) string {
	t.Helper()
	_, req := w.start(t)
	resp, err := w.idp.Response(context.Background(), req, subject, samlidp.WithCustomBinding(w.binding))
	if err != nil {
		t.Fatal(err)
	}
	return resp.RedirectURL().Query().Get("SAMLart")
}

// signedResolve returns an ArtifactResolve of SP 1 for art, signed by it,
// as XML.
func (w *world) signedResolve(t *testing.T, art string) string {
	t.Helper()
	return w.signedResolveWith(t, art, func(*saml.ArtifactResolve) {})
}

// signedResolveWith is signedResolve, with the request changed by modify
// before it is signed.
func (w *world) signedResolveWith(t *testing.T, art string, modify func(*saml.ArtifactResolve)) string {
	t.Helper()
	req := &saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: &saml.Issuer{Value: w.sps[0].EntityID()}, Artifact: art,
	}
	modify(req)
	signed, err := w.sps[0].SignElement(req.Element())
	if err != nil {
		t.Fatal(err)
	}
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// post posts body to b as a SOAP request.
func post(b http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, r)
	return rec
}

// carriesResponse reports whether rec is an ArtifactResponse that carries
// a Response.
func carriesResponse(t *testing.T, rec *httptest.ResponseRecorder) bool {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("ArtifactResolutionService: %d %s", rec.Code, rec.Body.String())
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(rec.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	return doc.FindElement("/Envelope/Body/ArtifactResponse/Response") != nil
}

// TestResolveChecksSOAPEnvelope checks that a signed ArtifactResolve is
// refused, and passed to OnError, in an envelope that package saml would
// refuse: one that is not XML encoding/xml reads as written, not a SOAP
// 1.1 Envelope, with a mandatory header, or with more in its Body.
func TestResolveChecksSOAPEnvelope(t *testing.T) {
	var refused []error
	w := newWorld(t, func(b *idpartifact.Binding) {
		b.OnError = func(_ *http.Request, err error) { refused = append(refused, err) }
	})
	resolve := w.signedResolve(t, w.artifact(t))

	for name, body := range map[string]string{
		"unstable XML": `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soapenv:Header><![CDATA[]]></soapenv:Header><soapenv:Body>` + resolve + soapEnd,
		"another namespace": `<soapenv:Envelope xmlns:soapenv="urn:example:not-soap"><soapenv:Body>` + resolve + soapEnd,
		"mandatory header": `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
			`<soapenv:Header><x:Tx xmlns:x="urn:example:tx" soapenv:mustUnderstand="1"/></soapenv:Header>` +
			`<soapenv:Body>` + resolve + soapEnd,
		"two elements in the Body": soapStart + resolve + `<x:Extra xmlns:x="urn:example:x"/>` + soapEnd,
		"no Body":                  `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"/>`,
	} {
		refused = nil
		if rec := post(w.binding, body); rec.Code != http.StatusInternalServerError || !strings.Contains(rec.Body.String(), "Fault") {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
		if len(refused) != 1 {
			t.Errorf("%s: OnError called with %v", name, refused)
		}
	}

	// The artifact was not used up.
	refused = nil
	if !carriesResponse(t, post(w.binding, soapStart+resolve+soapEnd)) {
		t.Error("the refused requests used up the artifact")
	}
	if refused != nil {
		t.Errorf("OnError called with %v", refused)
	}
}

// unsignableStore is a Store whose Take returns a message that cannot be
// signed in an ArtifactResponse.
type unsignableStore struct {
	*idpartifact.MemoryStore
}

func (s unsignableStore) Take(ctx context.Context, art, recipient string) (*idpartifact.StoredMessage, error) {
	m, err := s.MemoryStore.Take(ctx, art, recipient)
	if m != nil {
		m.XML = []byte(`<p:x/>`) // an undeclared prefix, which cannot be canonicalized
	}
	return m, err
}

// TestResolveKeepsMessageWhenSigningFails checks that a message taken from
// the store is put back if the ArtifactResponse that would carry it
// cannot be made.
func TestResolveKeepsMessageWhenSigningFails(t *testing.T) {
	var refused error
	w := newWorld(t, nil)
	w.binding = newBinding(t, w.idp, unsignableStore{w.store}, 3)
	w.binding.OnError = func(_ *http.Request, err error) { refused = err }
	rec := post(w.binding, soapStart+w.signedResolve(t, w.artifact(t))+soapEnd)
	if rec.Code != http.StatusInternalServerError || refused == nil {
		t.Fatalf("%d %s, OnError %v", rec.Code, rec.Body.String(), refused)
	}
	if w.store.Len() != 1 {
		t.Errorf("%d messages stored after a failed ArtifactResponse, want 1", w.store.Len())
	}
}

// An ArtifactResolve must be SAML 2.0, have an Issuer with no Format or
// the entity Format (saml-profiles §5.4.1) and, if it has a Destination, be
// addressed to this ArtifactResolutionService (saml-core §3.2.1, §3.2.2).
func TestResolveChecksVersionAndDestination(t *testing.T) {
	w := newWorld(t, nil)
	art := w.artifact(t)
	for name, modify := range map[string]func(*saml.ArtifactResolve){
		"SAML 1.1":          func(r *saml.ArtifactResolve) { r.Version = "1.1" },
		"other Destination": func(r *saml.ArtifactResolve) { r.Destination = "https://other.example.com/saml/artifact" },
		"Issuer Format not entity": func(r *saml.ArtifactResolve) {
			r.Issuer.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
		},
	} {
		if rec := post(w.binding, soapStart+w.signedResolveWith(t, art, modify)+soapEnd); rec.Code != http.StatusInternalServerError {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body.String())
		}
	}
	right := w.signedResolveWith(t, art, func(r *saml.ArtifactResolve) {
		r.Destination = w.server.URL + "/saml/artifact"
		r.Issuer.Format = "urn:oasis:names:tc:SAML:2.0:nameid-format:entity"
	})
	if !carriesResponse(t, post(w.binding, soapStart+right+soapEnd)) {
		t.Error("the right Destination: no Response")
	}
}
