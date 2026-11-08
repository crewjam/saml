package artifact_test

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/artifact"
)

// resolveXML returns a SOAP envelope with an ArtifactResolve for art,
// issued by issuer at issueInstant, and signed with key unless it is nil.
func resolveXML(t *testing.T, art, issuer string, issueInstant time.Time, key *rsa.PrivateKey, cert *x509.Certificate) string {
	t.Helper()
	el := (&saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: issueInstant,
		Issuer: &saml.Issuer{Value: issuer}, Artifact: art,
	}).Element()
	if key != nil {
		signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: key, Certificate: [][]byte{cert.Raw}})
		signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		var err error
		if el, err = signer.SignEnveloped(el); err != nil {
			t.Fatal(err)
		}
	}
	env := etree.NewElement("soapenv:Envelope")
	env.CreateAttr("xmlns:soapenv", "http://schemas.xmlsoap.org/soap/envelope/")
	env.CreateElement("soapenv:Body").AddChild(el)
	doc := etree.NewDocument()
	doc.SetRoot(env)
	body, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// postTLS posts body to b as a SOAP request over a TLS connection on
// which the client presented peer, or none if peer is nil.
func postTLS(b http.Handler, body string, peer *x509.Certificate) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, arsURL, strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	r.TLS = &tls.ConnectionState{HandshakeComplete: true}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

func isFault(w *httptest.ResponseRecorder) bool {
	return w.Code == http.StatusInternalServerError && strings.Contains(w.Body.String(), "Fault")
}

func TestTLSClientAuth(t *testing.T) {
	idp, cfg, b, store, spCert := setup(t)
	var errs []error
	b.OnError = func(_ *http.Request, err error) { errs = append(errs, err) }
	newArt := func() string {
		msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		return msg.RedirectURL().Query().Get("SAMLart")
	}
	art := newArt()
	unsigned := resolveXML(t, art, idpEntityID, time.Now().UTC(), nil, nil)
	_, otherCert := keyPair(t)

	// Off by default: an unsigned request is refused, even with the IdP's
	// certificate.
	if w := postTLS(b, unsigned, idp.cert); !isFault(w) {
		t.Errorf("TLSClientAuth off: %d", w.Code)
	}

	b.TLSClientAuth = true
	if w := postTLS(b, unsigned, nil); !isFault(w) {
		t.Errorf("no client certificate: %d", w.Code)
	}
	if w := postTLS(b, unsigned, otherCert); !isFault(w) {
		t.Errorf("another client certificate: %d", w.Code)
	}
	// Not fresh, or issued by someone else.
	if w := postTLS(b, resolveXML(t, art, idpEntityID, time.Now().UTC().Add(-saml.MaxIssueDelay-time.Minute), nil, nil), idp.cert); !isFault(w) {
		t.Errorf("stale request: %d", w.Code)
	}
	if w := postTLS(b, resolveXML(t, art, "https://other.example.com", time.Now().UTC(), nil, nil), idp.cert); !isFault(w) {
		t.Errorf("another issuer: %d", w.Code)
	}
	// A signature that does not verify is refused, though the client
	// certificate would do: there is no falling back.
	tampered := strings.Replace(resolveXML(t, art, idpEntityID, time.Now().UTC(), idp.key, idp.cert), "id-resolve-1", "id-resolve-2", 1)
	if w := postTLS(b, tampered, idp.cert); !isFault(w) {
		t.Errorf("tampered signature: %d", w.Code)
	}
	otherKey, _ := keyPair(t)
	if w := postTLS(b, resolveXML(t, art, idpEntityID, time.Now().UTC(), otherKey, otherCert), idp.cert); !isFault(w) {
		t.Errorf("signed by another key: %d", w.Code)
	}
	if len(errs) != 7 {
		t.Errorf("OnError called %d times, want 7: %v", len(errs), errs)
	}
	if store.Len() != 1 {
		t.Fatal("the refused requests used up the artifact")
	}

	// The IdP's certificate, presented by TLS, resolves the artifact, once.
	got := artifactResponse(t, postTLS(b, unsigned, idp.cert), spCert)
	if got == nil || got.Tag != "AuthnRequest" {
		t.Fatalf("got %v", got)
	}
	if again := artifactResponse(t, postTLS(b, unsigned, idp.cert), spCert); again != nil {
		t.Error("the artifact was resolved twice")
	}

	// A signed request still works, with or without a certificate.
	art = newArt()
	if got := artifactResponse(t, postTLS(b, resolveXML(t, art, idpEntityID, time.Now().UTC(), idp.key, idp.cert), otherCert), spCert); got == nil {
		t.Error("a signed request was refused")
	}

	// Namespaces that the ArtifactResolve inherits from the envelope.
	art = newArt()
	inherited := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><soapenv:Body>` +
		`<samlp:ArtifactResolve ID="id-resolve-1" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `">` +
		`<saml:Issuer>` + idpEntityID + `</saml:Issuer><samlp:Artifact>` + art + `</samlp:Artifact>` +
		`</samlp:ArtifactResolve>` + soapEnd
	if got := artifactResponse(t, postTLS(b, inherited, idp.cert), spCert); got == nil {
		t.Error("an ArtifactResolve with inherited namespaces was not resolved")
	}

	// A certificate whose key is in the metadata for encryption only does
	// not count.
	_, encCert := keyPair(t)
	md := idp.metadata()
	md.IDPSSODescriptors[0].KeyDescriptors = append(md.IDPSSODescriptors[0].KeyDescriptors, saml.KeyDescriptor{Use: "encryption",
		KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(encCert.Raw)}}}}})
	spKey, spCert2 := keyPair(t)
	cfg2, err := samlsp.New(spEntityID, samlsp.StaticMetadata(md), samlsp.WithSigningKey(spKey, spCert2), artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	b2 := newBinding(t, cfg2, artifact.NewMemoryStore())
	b2.TLSClientAuth = true
	msg, err := cfg2.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b2))
	if err != nil {
		t.Fatal(err)
	}
	if w := postTLS(b2, resolveXML(t, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, time.Now().UTC(), nil, nil), encCert); !isFault(w) {
		t.Errorf("an encryption certificate: %d", w.Code)
	}
}

// TestTLSClientAuthClientCertificate checks that ClientCertificate stands
// in for r.TLS, behind a proxy that terminates TLS.
func TestTLSClientAuthClientCertificate(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	b.TLSClientAuth = true
	b.ClientCertificate = func(r *http.Request) *x509.Certificate {
		if r.Header.Get("X-Client-Cert") == "idp" {
			return idp.cert
		}
		return nil
	}
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	body := resolveXML(t, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, time.Now().UTC(), nil, nil)
	post := func(header string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, arsURL, strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")
		if header != "" {
			r.Header.Set("X-Client-Cert", header)
		}
		// r.TLS is ignored, with ClientCertificate set.
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{idp.cert}}
		w := httptest.NewRecorder()
		b.ServeHTTP(w, r)
		return w
	}
	if w := post(""); !isFault(w) {
		t.Errorf("no forwarded certificate: %d", w.Code)
	}
	if got := artifactResponse(t, post("idp"), spCert); got == nil {
		t.Error("the forwarded certificate was not accepted")
	}
}

// TestTLSClientAuthOtherIdP checks that a client certificate of one IdP
// does not authenticate a request that names another as its Issuer, and
// that it resolves for its own IdP only the artifacts meant for it.
func TestTLSClientAuthOtherIdP(t *testing.T) {
	const otherEntityID = "https://idp-b.example.com/metadata"
	idpA := &fakeIDP{}
	idpA.key, idpA.cert = keyPair(t)
	idpB := &fakeIDP{}
	idpB.key, idpB.cert = keyPair(t)
	mdB := idpB.metadata()
	mdB.EntityID = otherEntityID
	idps := map[string]samlsp.MetadataFunc{
		idpEntityID:   samlsp.StaticMetadata(idpA.metadata()),
		otherEntityID: samlsp.StaticMetadata(mdB),
	}
	spKey, spCert := keyPair(t)
	cfg, err := samlsp.New(spEntityID, nil, samlsp.WithSigningKey(spKey, spCert), artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	b := newBinding(t, cfg, artifact.NewMemoryStore())
	b.TLSClientAuth = true
	b.IdentityProvider = func(_ context.Context, entityID string) (samlsp.MetadataFunc, error) {
		if idp, ok := idps[entityID]; ok {
			return idp, nil
		}
		return nil, errors.New("unknown IdP")
	}
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b), samlsp.WithIdentityProvider(idps[idpEntityID]))
	if err != nil {
		t.Fatal(err)
	}
	art := msg.RedirectURL().Query().Get("SAMLart")

	if w := postTLS(b, resolveXML(t, art, idpEntityID, time.Now().UTC(), nil, nil), idpB.cert); !isFault(w) {
		t.Errorf("IdP B's certificate for IdP A: %d", w.Code)
	}
	if got := artifactResponse(t, postTLS(b, resolveXML(t, art, otherEntityID, time.Now().UTC(), nil, nil), idpB.cert), spCert); got != nil {
		t.Error("IdP B was given the message for IdP A")
	}
	if got := artifactResponse(t, postTLS(b, resolveXML(t, art, idpEntityID, time.Now().UTC(), nil, nil), idpA.cert), spCert); got == nil {
		t.Error("IdP A could not resolve its artifact")
	}
}

// TestTLSClientAuthServer resolves an artifact over a real TLS connection
// on which the server asks for a client certificate.
func TestTLSClientAuthServer(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	b.TLSClientAuth = true
	srv := httptest.NewUnstartedServer(b)
	srv.TLS = &tls.Config{ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	newArt := func() string {
		msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		return msg.RedirectURL().Query().Get("SAMLart")
	}
	post := func(client *http.Client, art string) *httptest.ResponseRecorder {
		t.Helper()
		resp, err := client.Post(srv.URL+b.Path(), "text/xml", strings.NewReader(resolveXML(t, art, idpEntityID, time.Now().UTC(), nil, nil)))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		w := httptest.NewRecorder()
		w.WriteHeader(resp.StatusCode)
		_, _ = w.Write(body)
		return w
	}
	withCert := func(key *rsa.PrivateKey, cert *x509.Certificate) *http.Client {
		c := srv.Client()
		tr := c.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
		c.Transport = tr
		return c
	}

	art := newArt()
	if w := post(srv.Client(), art); !isFault(w) {
		t.Errorf("no client certificate: %d", w.Code)
	}
	otherKey, otherCert := keyPair(t)
	if w := post(withCert(otherKey, otherCert), art); !isFault(w) {
		t.Errorf("another client certificate: %d", w.Code)
	}
	if got := artifactResponse(t, post(withCert(idp.key, idp.cert), art), spCert); got == nil {
		t.Error("the IdP's client certificate did not resolve the artifact")
	}
}
