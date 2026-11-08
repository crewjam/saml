package artifact_test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/artifact"
)

// signedResolve returns an ArtifactResolve for art, issued now by the IdP
// and signed by it, as XML.
func (idp *fakeIDP) signedResolve(t *testing.T, art string) string {
	t.Helper()
	req := &saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: &saml.Issuer{Value: idpEntityID}, Artifact: art,
	}
	return signedElement(t, req.Element(), idp.key, idp.cert)
}

// TestResolveChecksSOAPEnvelope checks that a signed ArtifactResolve is
// refused, and passed to OnError, in an envelope that package saml would
// refuse: one that is not XML encoding/xml reads as written, not a SOAP
// 1.1 Envelope, with a mandatory header, or with more in its Body.
func TestResolveChecksSOAPEnvelope(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	var refused []error
	b.OnError = func(_ *http.Request, err error) { refused = append(refused, err) }
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	art := msg.RedirectURL().Query().Get("SAMLart")
	resolve := idp.signedResolve(t, art)

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
		if w := postSOAP(b, body); w.Code != http.StatusInternalServerError || !strings.Contains(w.Body.String(), "Fault") {
			t.Errorf("%s: %d %s", name, w.Code, w.Body.String())
		}
		if len(refused) != 1 {
			t.Errorf("%s: OnError called with %v", name, refused)
		}
	}

	// A header that need not be understood is ignored, and the artifact
	// was not used up.
	refused = nil
	body := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/">` +
		`<soapenv:Header><x:Tx xmlns:x="urn:example:tx" soapenv:mustUnderstand="0"/></soapenv:Header>` +
		`<soapenv:Body>` + resolve + soapEnd
	if got := artifactResponse(t, postSOAP(b, body), spCert); got == nil || got.SelectAttrValue("ID", "") != msg.ID {
		t.Errorf("resolved %v, want the AuthnRequest", got)
	}
	if refused != nil {
		t.Errorf("OnError called with %v", refused)
	}
}

// unsignableStore is a Store whose Take returns a message that cannot be
// signed in an ArtifactResponse.
type unsignableStore struct {
	*artifact.MemoryStore
}

func (s unsignableStore) Take(ctx context.Context, art, recipient string) (*artifact.StoredMessage, error) {
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
	idp, cfg, _, _, _ := setup(t)
	store := unsignableStore{artifact.NewMemoryStore()}
	b := newBinding(t, cfg, store)
	var refused error
	b.OnError = func(_ *http.Request, err error) { refused = err }
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	w := idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert)
	if w.Code != http.StatusInternalServerError || refused == nil {
		t.Fatalf("%d %s, OnError %v", w.Code, w.Body.String(), refused)
	}
	if store.Len() != 1 {
		t.Errorf("%d messages stored after a failed ArtifactResponse, want 1", store.Len())
	}
}
