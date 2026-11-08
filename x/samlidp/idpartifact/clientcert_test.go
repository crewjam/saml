package idpartifact_test

import (
	"crypto/tls"
	"crypto/x509"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp/idpartifact"
)

// unsignedResolve returns an unsigned ArtifactResolve for art, issued by
// issuer at issueInstant, as XML.
func unsignedResolve(t *testing.T, art, issuer string, issueInstant time.Time) string {
	t.Helper()
	doc := etree.NewDocument()
	doc.SetRoot((&saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: issueInstant,
		Issuer: &saml.Issuer{Value: issuer}, Artifact: art,
	}).Element())
	out, err := doc.WriteToString()
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// postTLS posts body to b as a SOAP request over a TLS connection on
// which the client presented peer, or none if peer is nil.
func postTLS(b http.Handler, body string, peer *x509.Certificate) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	r.TLS = &tls.ConnectionState{HandshakeComplete: true}
	if peer != nil {
		r.TLS.PeerCertificates = []*x509.Certificate{peer}
	}
	rec := httptest.NewRecorder()
	b.ServeHTTP(rec, r)
	return rec
}

func isFault(rec *httptest.ResponseRecorder) bool {
	return rec.Code == http.StatusInternalServerError && strings.Contains(rec.Body.String(), "Fault")
}

func TestTLSClientAuth(t *testing.T) {
	var errs []error
	w := newWorld(t, func(b *idpartifact.Binding) {
		b.OnError = func(_ *http.Request, err error) { errs = append(errs, err) }
	})
	_, sp1Cert := keyPair(t, 1)
	_, sp2Cert := keyPair(t, 2)
	_, idpCert := keyPair(t, 0)
	sp1, sp2 := w.sps[0].EntityID(), w.sps[1].EntityID()
	art := w.artifact(t)
	unsigned := soapStart + unsignedResolve(t, art, sp1, time.Now().UTC()) + soapEnd

	// Off by default: an unsigned request is refused, even with the SP's
	// certificate.
	if rec := postTLS(w.binding, unsigned, sp1Cert); !isFault(rec) {
		t.Errorf("TLSClientAuth off: %d", rec.Code)
	}

	w.binding.TLSClientAuth = true
	if rec := postTLS(w.binding, unsigned, nil); !isFault(rec) {
		t.Errorf("no client certificate: %d", rec.Code)
	}
	if rec := postTLS(w.binding, unsigned, idpCert); !isFault(rec) {
		t.Errorf("another client certificate: %d", rec.Code)
	}
	// SP 2's certificate does not make it SP 1.
	if rec := postTLS(w.binding, unsigned, sp2Cert); !isFault(rec) {
		t.Errorf("SP 2's certificate for SP 1: %d", rec.Code)
	}
	if rec := postTLS(w.binding, soapStart+unsignedResolve(t, art, sp1, time.Now().UTC().Add(-saml.MaxIssueDelay-time.Minute))+soapEnd, sp1Cert); !isFault(rec) {
		t.Errorf("stale request: %d", rec.Code)
	}
	// A signature that does not verify is refused, though the client
	// certificate would do: there is no falling back.
	tampered := strings.Replace(w.signedResolve(t, art), "id-resolve-1", "id-resolve-2", 1)
	if rec := postTLS(w.binding, soapStart+tampered+soapEnd, sp1Cert); !isFault(rec) {
		t.Errorf("tampered signature: %d", rec.Code)
	}
	if len(errs) != 6 {
		t.Errorf("OnError called %d times, want 6: %v", len(errs), errs)
	}
	if w.store.Len() != 1 {
		t.Fatal("the refused requests used up the artifact")
	}

	// SP 2, authenticated as itself, is not given SP 1's Response.
	if carriesResponse(t, postTLS(w.binding, soapStart+unsignedResolve(t, art, sp2, time.Now().UTC())+soapEnd, sp2Cert)) {
		t.Error("SP 2 was given the Response for SP 1")
	}

	// SP 1's certificate, presented by TLS, resolves the artifact, once.
	if !carriesResponse(t, postTLS(w.binding, unsigned, sp1Cert)) {
		t.Fatal("SP 1's client certificate did not resolve the artifact")
	}
	if carriesResponse(t, postTLS(w.binding, unsigned, sp1Cert)) {
		t.Error("the artifact was resolved twice")
	}

	// A signed request still works, whatever the certificate.
	if !carriesResponse(t, postTLS(w.binding, soapStart+w.signedResolve(t, w.artifact(t))+soapEnd, idpCert)) {
		t.Error("a signed request was refused")
	}

	// Namespaces that the ArtifactResolve inherits from the envelope.
	inherited := `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/" xmlns:samlp="urn:oasis:names:tc:SAML:2.0:protocol"` +
		` xmlns:saml="urn:oasis:names:tc:SAML:2.0:assertion"><soapenv:Body>` +
		`<samlp:ArtifactResolve ID="id-resolve-1" Version="2.0" IssueInstant="` + time.Now().UTC().Format(time.RFC3339) + `">` +
		`<saml:Issuer>` + sp1 + `</saml:Issuer><samlp:Artifact>` + w.artifact(t) + `</samlp:Artifact>` +
		`</samlp:ArtifactResolve>` + soapEnd
	if !carriesResponse(t, postTLS(w.binding, inherited, sp1Cert)) {
		t.Error("an ArtifactResolve with inherited namespaces was not resolved")
	}
}

// TestTLSClientAuthClientCertificate checks that ClientCertificate stands
// in for r.TLS, behind a proxy that terminates TLS.
func TestTLSClientAuthClientCertificate(t *testing.T) {
	_, sp1Cert := keyPair(t, 1)
	w := newWorld(t, func(b *idpartifact.Binding) {
		b.TLSClientAuth = true
		b.ClientCertificate = func(r *http.Request) *x509.Certificate {
			if r.Header.Get("X-Client-Cert") == "sp1" {
				return sp1Cert
			}
			return nil
		}
	})
	body := soapStart + unsignedResolve(t, w.artifact(t), w.sps[0].EntityID(), time.Now().UTC()) + soapEnd
	post := func(header string) *httptest.ResponseRecorder {
		r := httptest.NewRequest(http.MethodPost, "/saml/artifact", strings.NewReader(body))
		r.Header.Set("Content-Type", "text/xml")
		if header != "" {
			r.Header.Set("X-Client-Cert", header)
		}
		// r.TLS is ignored, with ClientCertificate set.
		r.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{sp1Cert}}
		rec := httptest.NewRecorder()
		w.binding.ServeHTTP(rec, r)
		return rec
	}
	if rec := post(""); !isFault(rec) {
		t.Errorf("no forwarded certificate: %d", rec.Code)
	}
	if !carriesResponse(t, post("sp1")) {
		t.Error("the forwarded certificate was not accepted")
	}
}

// TestTLSClientAuthServer resolves an artifact over a real TLS connection
// on which the server asks for a client certificate.
func TestTLSClientAuthServer(t *testing.T) {
	w := newWorld(t, func(b *idpartifact.Binding) { b.TLSClientAuth = true })
	srv := httptest.NewUnstartedServer(w.binding)
	srv.TLS = &tls.Config{ClientAuth: tls.RequireAnyClientCert, MinVersion: tls.VersionTLS12}
	srv.StartTLS()
	t.Cleanup(srv.Close)

	post := func(i int, art string) *httptest.ResponseRecorder {
		t.Helper()
		key, cert := keyPair(t, i)
		c := srv.Client()
		tr := c.Transport.(*http.Transport).Clone()
		tr.TLSClientConfig.Certificates = []tls.Certificate{{Certificate: [][]byte{cert.Raw}, PrivateKey: key}}
		c.Transport = tr
		body := soapStart + unsignedResolve(t, art, w.sps[0].EntityID(), time.Now().UTC()) + soapEnd
		resp, err := c.Post(srv.URL+w.binding.Path(), "text/xml", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		defer func() { _ = resp.Body.Close() }()
		got, err := io.ReadAll(resp.Body)
		if err != nil {
			t.Fatal(err)
		}
		rec := httptest.NewRecorder()
		rec.WriteHeader(resp.StatusCode)
		_, _ = rec.Write(got)
		return rec
	}
	art := w.artifact(t)
	if rec := post(2, art); !isFault(rec) {
		t.Errorf("SP 2's client certificate: %d", rec.Code)
	}
	if !carriesResponse(t, post(1, art)) {
		t.Error("SP 1's client certificate did not resolve the artifact")
	}
}
