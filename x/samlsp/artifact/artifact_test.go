package artifact_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha1" //nolint:gosec // to check the artifact's SourceID
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"html"
	"math/big"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
	"github.com/crewjam/saml/x/samlsp/artifact"
	"github.com/crewjam/saml/x/samlsp/slo"
)

const (
	idpEntityID = "https://idp.example.com/metadata"
	spEntityID  = "https://sp.example.com/saml/metadata"
	arsURL      = "https://sp.example.com/saml/artifact"
)

func keyPair(t *testing.T) (*rsa.PrivateKey, *x509.Certificate) {
	t.Helper()
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "test"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return key, cert
}

// fakeIDP plays the IdP's part of the HTTP-Artifact binding.
type fakeIDP struct {
	key  *rsa.PrivateKey
	cert *x509.Certificate
}

func (idp *fakeIDP) metadata() *saml.EntityDescriptor {
	endpoints := func(path string) []saml.Endpoint {
		return []saml.Endpoint{
			{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/" + path},
			{Binding: saml.HTTPArtifactBinding, Location: "https://idp.example.com/" + path + "-artifact"},
		}
	}
	return &saml.EntityDescriptor{
		EntityID: idpEntityID,
		IDPSSODescriptors: []saml.IDPSSODescriptor{{
			SSODescriptor: saml.SSODescriptor{
				RoleDescriptor: saml.RoleDescriptor{
					ProtocolSupportEnumeration: "urn:oasis:names:tc:SAML:2.0:protocol",
					KeyDescriptors: []saml.KeyDescriptor{{Use: "signing", KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
						X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(idp.cert.Raw)}},
					}}}},
				},
				SingleLogoutServices: endpoints("slo"),
			},
			SingleSignOnServices: endpoints("sso"),
		}},
	}
}

// resolve sends the SP an ArtifactResolve for art, issued by issuer and
// signed with key (unsigned if key is nil), and returns the SP's answer.
func (idp *fakeIDP) resolve(t *testing.T, b http.Handler, art, issuer string, key *rsa.PrivateKey, cert *x509.Certificate) *httptest.ResponseRecorder {
	t.Helper()
	return idp.resolveAt(t, b, art, issuer, key, cert, time.Now().UTC())
}

// resolveAt is resolve with an ArtifactResolve issued at issueInstant.
func (idp *fakeIDP) resolveAt(t *testing.T, b http.Handler, art, issuer string, key *rsa.PrivateKey, cert *x509.Certificate, issueInstant time.Time) *httptest.ResponseRecorder {
	t.Helper()
	req := &saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: issueInstant,
		Issuer: &saml.Issuer{Value: issuer}, Artifact: art,
	}
	el := req.Element()
	if key != nil {
		signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: key, Certificate: [][]byte{cert.Raw}})
		signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
		if err := signer.SetSignatureMethod(dsig.RSASHA256SignatureMethod); err != nil {
			t.Fatal(err)
		}
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
	return postSOAP(b, body)
}

// postSOAP posts body to b as a SOAP request.
func postSOAP(b http.Handler, body string) *httptest.ResponseRecorder {
	r := httptest.NewRequest(http.MethodPost, arsURL, strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
}

// signedElement returns el signed with key, as XML.
func signedElement(t *testing.T, el *etree.Element, key *rsa.PrivateKey, cert *x509.Certificate) string {
	t.Helper()
	signer := dsig.NewDefaultSigningContext(dsig.TLSCertKeyStore{PrivateKey: key, Certificate: [][]byte{cert.Raw}})
	signer.Canonicalizer = dsig.MakeC14N10ExclusiveCanonicalizerWithPrefixList("")
	signed, err := signer.SignEnveloped(el)
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

const (
	soapStart = `<soapenv:Envelope xmlns:soapenv="http://schemas.xmlsoap.org/soap/envelope/"><soapenv:Body>`
	soapEnd   = `</soapenv:Body></soapenv:Envelope>`
)

func TestResolveRefusesBadRequests(t *testing.T) {
	idp, cfg, b, store, spCert := setup(t)
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	art := msg.RedirectURL().Query().Get("SAMLart")
	isFault := func(w *httptest.ResponseRecorder) bool {
		return w.Code == http.StatusInternalServerError && strings.Contains(w.Body.String(), "Fault")
	}

	// Issued too long ago, or too far in the future: the IdP's request is
	// not fresh.
	if w := idp.resolveAt(t, b, art, idpEntityID, idp.key, idp.cert, time.Now().UTC().Add(-saml.MaxIssueDelay-time.Minute)); !isFault(w) {
		t.Errorf("stale request: %d", w.Code)
	}
	if w := idp.resolveAt(t, b, art, idpEntityID, idp.key, idp.cert, time.Now().UTC().Add(saml.MaxClockSkew+time.Minute)); !isFault(w) {
		t.Errorf("request from the future: %d", w.Code)
	}

	// Not XML, too large, or not an ArtifactResolve.
	if w := postSOAP(b, soapStart+"<oops"); !isFault(w) {
		t.Errorf("malformed XML: %d", w.Code)
	}
	if w := postSOAP(b, soapStart+strings.Repeat(" ", 64<<10)+soapEnd); !isFault(w) {
		t.Errorf("oversized request: %d", w.Code)
	}
	logoutReq := (&saml.LogoutRequest{ID: "id-x", Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: &saml.Issuer{Value: idpEntityID}, NameID: &saml.NameID{Value: "alice"}}).Element()
	if w := postSOAP(b, soapStart+signedElement(t, logoutReq, idp.key, idp.cert)+soapEnd); !isFault(w) {
		t.Errorf("a LogoutRequest instead: %d", w.Code)
	}
	// An ArtifactResolve in the wrong namespace.
	wrongNS := etree.NewElement("ArtifactResolve")
	wrongNS.CreateAttr("xmlns", "urn:example:not-saml")
	wrongNS.CreateAttr("ID", "id-y")
	if w := postSOAP(b, soapStart+signedElement(t, wrongNS, idp.key, idp.cert)+soapEnd); !isFault(w) {
		t.Errorf("wrong namespace: %d", w.Code)
	}
	// No ID.
	noID := (&saml.ArtifactResolve{Version: "2.0", IssueInstant: time.Now().UTC(),
		Issuer: &saml.Issuer{Value: idpEntityID}, Artifact: art}).Element()
	noID.RemoveAttr("ID")
	noID.CreateAttr("ID", "")
	if w := postSOAP(b, soapStart+signedElement(t, noID, idp.key, idp.cert)+soapEnd); !isFault(w) {
		t.Errorf("no ID: %d", w.Code)
	}

	// None of these used up the artifact.
	if store.Len() != 1 {
		t.Fatalf("%d messages stored, want 1", store.Len())
	}
	if got := artifactResponse(t, idp.resolve(t, b, art, idpEntityID, idp.key, idp.cert), spCert); got == nil {
		t.Error("the refused requests used up the artifact")
	}
}

// artifactResponse checks the SP's answer, signed with spCert, and returns
// the message it carries, or nil.
func artifactResponse(t *testing.T, w *httptest.ResponseRecorder, spCert *x509.Certificate) *etree.Element {
	t.Helper()
	if w.Code != http.StatusOK {
		t.Fatalf("ArtifactResolutionService: %d %s", w.Code, w.Body.String())
	}
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	resp := doc.FindElement("/Envelope/Body/ArtifactResponse")
	if resp == nil {
		t.Fatalf("no ArtifactResponse: %s", w.Body.String())
	}
	if resp.ChildElements()[1].Tag != "Signature" {
		t.Error("the Signature is not right after the Issuer")
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{spCert}})
	vc.IdAttribute = "ID"
	verified, err := vc.Validate(resp)
	if err != nil {
		t.Fatalf("the ArtifactResponse is not signed by the SP: %v", err)
	}
	if verified.SelectAttrValue("InResponseTo", "") != "id-resolve-1" ||
		verified.FindElement("./Issuer").Text() != spEntityID ||
		verified.FindElement("./Status/StatusCode").SelectAttrValue("Value", "") != saml.StatusSuccess {
		t.Errorf("ArtifactResponse: %s", w.Body.String())
	}
	for _, c := range verified.ChildElements() {
		if c.Tag == "AuthnRequest" || c.Tag == "LogoutRequest" || c.Tag == "LogoutResponse" {
			return c
		}
	}
	return nil
}

func setup(t *testing.T) (*fakeIDP, *samlsp.Config, *artifact.Binding, *artifact.MemoryStore, *x509.Certificate) {
	t.Helper()
	idpKey, idpCert := keyPair(t)
	idp := &fakeIDP{key: idpKey, cert: idpCert}
	spKey, spCert := keyPair(t)
	cfg, err := samlsp.New(spEntityID, samlsp.StaticMetadata(idp.metadata()),
		samlsp.WithSigningKey(spKey, spCert), samlsp.SignAuthnRequests,
		slo.Endpoint("https://sp.example.com/saml/slo"),
		artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.NewMemoryStore()
	return idp, cfg, newBinding(t, cfg, store, 3), store, spCert
}

func TestAuthnRequestByArtifact(t *testing.T) {
	idp, cfg, b, store, spCert := setup(t)

	msg, err := cfg.AuthnRequest(t.Context(), "relay-1", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	u := msg.RedirectURL()
	if msg.Binding != saml.HTTPArtifactBinding || u.Host+u.Path != "idp.example.com/sso-artifact" || u.Query().Get("RelayState") != "relay-1" {
		t.Fatalf("redirect to %v", u)
	}
	art := u.Query().Get("SAMLart")

	// A type 0x0004 artifact: endpoint index 3, the SHA-1 of the SP's
	// entity ID, and a 20-byte handle.
	raw, err := base64.StdEncoding.DecodeString(art)
	if err != nil || len(raw) != 44 {
		t.Fatalf("artifact %q: %v", art, err)
	}
	source := sha1.Sum([]byte(spEntityID)) //nolint:gosec // see the import
	if binary.BigEndian.Uint16(raw[0:2]) != 4 || binary.BigEndian.Uint16(raw[2:4]) != 3 || string(raw[4:24]) != string(source[:]) {
		t.Errorf("artifact header %x", raw[:24])
	}

	// The IdP resolves it and gets the signed AuthnRequest.
	got := artifactResponse(t, idp.resolve(t, b, art, idpEntityID, idp.key, idp.cert), spCert)
	if got == nil {
		t.Fatal("no message in the ArtifactResponse")
	}
	if got.SelectAttrValue("ID", "") != msg.ID || got.SelectAttrValue("Destination", "") != "https://idp.example.com/sso-artifact" {
		t.Errorf("AuthnRequest %s %s", got.SelectAttrValue("ID", ""), got.SelectAttrValue("Destination", ""))
	}
	if got.FindElement("./Signature") == nil {
		t.Error("the AuthnRequest is not signed, though SignAuthnRequests is set")
	}

	// Only once.
	if again := artifactResponse(t, idp.resolve(t, b, art, idpEntityID, idp.key, idp.cert), spCert); again != nil {
		t.Error("the artifact was resolved twice")
	}
	if store.Len() != 0 {
		t.Errorf("%d messages still stored", store.Len())
	}
}

func TestLogoutByArtifact(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)

	logout, err := slo.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := logout.Request(t.Context(), saml.NameID{Value: "alice"}, "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactResponse(t, idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert), spCert); got == nil || got.Tag != "LogoutRequest" {
		t.Fatalf("got %v", got)
	}

	msg, err = logout.Response(t.Context(), &slo.Request{ID: "id-idp-logout"}, samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	got := artifactResponse(t, idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert), spCert)
	if got == nil || got.Tag != "LogoutResponse" || got.SelectAttrValue("InResponseTo", "") != "id-idp-logout" {
		t.Fatalf("got %v", got)
	}
}

func TestResolveRefused(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	newArt := func() string {
		msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
		if err != nil {
			t.Fatal(err)
		}
		return msg.RedirectURL().Query().Get("SAMLart")
	}
	isFault := func(w *httptest.ResponseRecorder) bool {
		return w.Code == http.StatusInternalServerError && strings.Contains(w.Body.String(), "Fault")
	}

	// Unsigned, signed by another key, or issued by someone else: a fault,
	// and the message stays for the real IdP.
	art := newArt()
	if w := idp.resolve(t, b, art, idpEntityID, nil, nil); !isFault(w) {
		t.Errorf("unsigned: %d %s", w.Code, w.Body.String())
	}
	otherKey, otherCert := keyPair(t)
	if w := idp.resolve(t, b, art, idpEntityID, otherKey, otherCert); !isFault(w) {
		t.Errorf("signed by another key: %d", w.Code)
	}
	if w := idp.resolve(t, b, art, "https://other.example.com", idp.key, idp.cert); !isFault(w) {
		t.Errorf("another issuer: %d", w.Code)
	}
	if got := artifactResponse(t, idp.resolve(t, b, art, idpEntityID, idp.key, idp.cert), spCert); got == nil {
		t.Error("the refused requests used up the artifact")
	}

	// An unknown artifact: success, with no message.
	if got := artifactResponse(t, idp.resolve(t, b, "AAQAAA==", idpEntityID, idp.key, idp.cert), spCert); got != nil {
		t.Error("a message for an unknown artifact")
	}

	// Not SOAP.
	w := httptest.NewRecorder()
	b.ServeHTTP(w, httptest.NewRequest(http.MethodGet, arsURL, nil))
	if !isFault(w) {
		t.Errorf("GET: %d", w.Code)
	}
}

func TestExpiredArtifact(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	b.Lifetime = 10 * time.Millisecond
	msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	time.Sleep(50 * time.Millisecond)
	if got := artifactResponse(t, idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert), spCert); got != nil {
		t.Error("an expired artifact was resolved")
	}
}

func TestResolutionServiceMetadata(t *testing.T) {
	_, cfg, _, _, _ := setup(t)
	ars := cfg.Metadata(context.Background()).SPSSODescriptors[0].ArtifactResolutionServices
	if len(ars) != 1 || ars[0].Location != arsURL || ars[0].Index != 3 || ars[0].Binding != saml.SOAPBinding {
		t.Errorf("ArtifactResolutionServices = %+v", ars)
	}
}

func TestMemoryStoreExpires(t *testing.T) {
	s := artifact.NewMemoryStore()
	ctx := context.Background()
	if err := s.Save(ctx, "a", artifact.StoredMessage{XML: []byte("<x/>"), ExpiresAt: time.Now().Add(10 * time.Millisecond)}); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for s.Len() != 0 {
		if time.Now().After(deadline) {
			t.Fatal("the message was not forgotten when it expired")
		}
		time.Sleep(5 * time.Millisecond)
	}
	if m, err := s.Take(ctx, "a", ""); m != nil || err != nil {
		t.Errorf("Take = %v, %v", m, err)
	}
}

// TestMemoryStoreTakeRecipient checks that only the recipient can take a
// message, and that another party's attempt leaves it in place.
func TestMemoryStoreTakeRecipient(t *testing.T) {
	var s artifact.MemoryStore // the zero value is ready to use
	ctx := context.Background()
	m := artifact.StoredMessage{XML: []byte("<x/>"), Recipient: "https://idp.example.com", ExpiresAt: time.Now().Add(time.Minute)}
	if err := s.Save(ctx, "a", m); err != nil {
		t.Fatal(err)
	}
	if got, err := s.Take(ctx, "a", "https://other.example.com"); got != nil || err != nil {
		t.Errorf("another party took the message: %v, %v", got, err)
	}
	if got, err := s.Take(ctx, "a", m.Recipient); err != nil || got == nil || string(got.XML) != "<x/>" {
		t.Errorf("the recipient's Take = %v, %v", got, err)
	}
	if got, _ := s.Take(ctx, "a", m.Recipient); got != nil {
		t.Error("a message was given out twice")
	}
}

// TestMemoryStoreClock checks that messages expire by the store's Clock:
// a message valid for a minute by a clock set in the past is kept.
func TestMemoryStoreClock(t *testing.T) {
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	s := &artifact.MemoryStore{Clock: dsig.NewFakeClockAt(past)}
	if err := s.Save(context.Background(), "a", artifact.StoredMessage{ExpiresAt: past.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if s.Len() != 1 {
		t.Error("the message expired by the system clock")
	}
}

var (
	formInput = regexp.MustCompile(`name="([A-Za-z]+)" value="([^"]*)"`)
	formTag   = regexp.MustCompile(`<form method="post" action="([^"]*)"`)
	scriptTag = regexp.MustCompile(`(?s)<script( nonce="[^"]*")?>(.*?)</script>`)
	cspHash   = regexp.MustCompile(`'(sha256-[^']+)'`)
)

func TestAuthnRequestByArtifactForm(t *testing.T) {
	idp, cfg, b, _, spCert := setup(t)
	b.Form = true

	msg, err := cfg.AuthnRequest(t.Context(), `relay "<1>"`, samlsp.WithCustomBinding(b), samlsp.WithScriptNonce("n0nce"))
	if err != nil {
		t.Fatal(err)
	}
	if msg.RedirectURL() != nil {
		t.Fatal("a form message has a redirect URL")
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	body := w.Body.String()

	if w.Code != http.StatusOK || w.Header().Get("Content-Type") != "text/html; charset=utf-8" ||
		w.Header().Get("Cache-Control") != "no-cache, no-store" {
		t.Fatalf("%d %v", w.Code, w.Header())
	}
	if m := formTag.FindStringSubmatch(body); m == nil || m[1] != "https://idp.example.com/sso-artifact" {
		t.Errorf("form action: %s", body)
	}
	fields := map[string]string{}
	for _, m := range formInput.FindAllStringSubmatch(body, -1) {
		fields[m[1]] = html.UnescapeString(m[2])
	}
	if fields["RelayState"] != `relay "<1>"` {
		t.Errorf("RelayState %q, escaped wrongly in %s", fields["RelayState"], body)
	}
	if strings.Contains(body, `"<1>"`) {
		t.Error("the RelayState is not escaped")
	}

	// The CSP allows the script, by hash, and the script has the nonce.
	script := scriptTag.FindStringSubmatch(body)
	if script == nil || script[1] != ` nonce="n0nce"` {
		t.Fatalf("script: %s", body)
	}
	sum := sha256.Sum256([]byte(script[2]))
	want := "sha256-" + base64.StdEncoding.EncodeToString(sum[:])
	if got := cspHash.FindStringSubmatch(w.Header().Get("Content-Security-Policy")); got == nil || got[1] != want {
		t.Errorf("CSP %q does not allow the script %s", w.Header().Get("Content-Security-Policy"), want)
	}

	// The posted artifact resolves to the AuthnRequest.
	got := artifactResponse(t, idp.resolve(t, b, fields["SAMLart"], idpEntityID, idp.key, idp.cert), spCert)
	if got == nil || got.SelectAttrValue("ID", "") != msg.ID {
		t.Fatalf("resolved %v", got)
	}
}

// brokenStore is a Store whose Take fails, or returns a corrupt message.
type brokenStore struct {
	artifact.Store
	takeErr error
	corrupt bool
}

func (s brokenStore) Take(ctx context.Context, art, recipient string) (*artifact.StoredMessage, error) {
	if s.takeErr != nil {
		return nil, s.takeErr
	}
	m, err := s.Store.Take(ctx, art, recipient)
	if m != nil && s.corrupt {
		m.XML = []byte("<not xml")
	}
	return m, err
}

func TestResolveFailures(t *testing.T) {
	isFault := func(w *httptest.ResponseRecorder) bool {
		return w.Code == http.StatusInternalServerError && strings.Contains(w.Body.String(), "Fault")
	}
	for name, store := range map[string]artifact.Store{
		"store fails":     brokenStore{Store: artifact.NewMemoryStore(), takeErr: errors.New("database down")},
		"corrupt message": brokenStore{Store: artifact.NewMemoryStore(), corrupt: true},
	} {
		t.Run(name, func(t *testing.T) {
			idp, cfg, _, _, _ := setup(t)
			b := newBinding(t, cfg, store, 3)
			msg, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b))
			if err != nil {
				t.Fatal(err)
			}
			if w := idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert); !isFault(w) {
				t.Errorf("%d %s", w.Code, w.Body.String())
			}
		})
	}

	// The IdP's metadata cannot be had when the request comes.
	idp, _, _, _, _ := setup(t)
	spKey, spCert := keyPair(t)
	down, err := samlsp.New(spEntityID, func(context.Context) (*saml.EntityDescriptor, error) {
		return nil, errors.New("metadata unavailable")
	}, samlsp.WithSigningKey(spKey, spCert), artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	b := newBinding(t, down, artifact.NewMemoryStore(), 3)
	if w := idp.resolve(t, b, "AAQAAA==", idpEntityID, idp.key, idp.cert); !isFault(w) {
		t.Errorf("metadata unavailable: %d", w.Code)
	}
}

// TestIdentityProviderPerCall sends an AuthnRequest by artifact for a
// Config made without an IdP: the IdP named for the call reaches the
// Binding through the context, and middleware names it for the
// ArtifactResolutionService, which no call option reaches.
func TestIdentityProviderPerCall(t *testing.T) {
	idpKey, idpCert := keyPair(t)
	idp := &fakeIDP{key: idpKey, cert: idpCert}
	spKey, spCert := keyPair(t)
	cfg, err := samlsp.New(spEntityID, nil, samlsp.WithSigningKey(spKey, spCert),
		artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	b := newBinding(t, cfg, artifact.NewMemoryStore(), 3)
	idpMetadata := samlsp.StaticMetadata(idp.metadata())

	msg, err := cfg.AuthnRequest(t.Context(), "relay-1",
		samlsp.WithCustomBinding(b), samlsp.WithIdentityProvider(idpMetadata))
	if err != nil {
		t.Fatal(err)
	}

	ars := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		b.ServeHTTP(w, r.WithContext(samlsp.IdentityProviderContext(r.Context(), idpMetadata)))
	})
	got := artifactResponse(t, idp.resolve(t, ars, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert), spCert)
	if got == nil || got.SelectAttrValue("ID", "") != msg.ID {
		t.Fatalf("resolved %v, want the AuthnRequest %s", got, msg.ID)
	}
}

// newBinding returns the Binding of New, failing t on an error.
func newBinding(t *testing.T, cfg *samlsp.Config, store artifact.Store, index uint16) *artifact.Binding {
	t.Helper()
	b, err := artifact.New(cfg, store, index)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestPath(t *testing.T) {
	_, cfg, b, _, _ := setup(t)
	if got := b.Path(); got != "/saml/artifact" {
		t.Errorf("Path = %q", got)
	}
	// An index the metadata does not advertise is refused, rather than
	// making artifacts that cannot be resolved and an empty Path.
	if _, err := artifact.New(cfg, artifact.NewMemoryStore(), 9); err == nil || !strings.Contains(err.Error(), "index 9") {
		t.Errorf("New with an index not advertised: %v", err)
	}
	// So is an SP with no ArtifactResolutionService at all.
	key, cert := keyPair(t)
	bare, err := samlsp.New(spEntityID, nil, samlsp.WithSigningKey(key, cert))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := artifact.New(bare, artifact.NewMemoryStore(), 3); err == nil {
		t.Error("New without a ResolutionService: accepted")
	}
}

// TestMemoryStoreClockFromConfig checks that New gives a MemoryStore with
// no Clock the clock of samlsp.WithClock, by which the Binding sets
// ExpiresAt: a message stored by a clock set in the past is kept for its
// lifetime, not forgotten at once by the system clock.
func TestMemoryStoreClockFromConfig(t *testing.T) {
	past := time.Date(2000, 1, 1, 0, 0, 0, 0, time.UTC)
	clock := dsig.NewFakeClockAt(past)
	idpKey, idpCert := keyPair(t)
	idp := &fakeIDP{key: idpKey, cert: idpCert}
	spKey, spCert := keyPair(t)
	cfg, err := samlsp.New(spEntityID, samlsp.StaticMetadata(idp.metadata()),
		samlsp.WithSigningKey(spKey, spCert), samlsp.WithClock(clock),
		artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.NewMemoryStore()
	b := newBinding(t, cfg, store, 3)
	if store.Clock != clock {
		t.Fatal("New did not set the store's Clock")
	}
	if _, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b)); err != nil {
		t.Fatal(err)
	}
	time.Sleep(20 * time.Millisecond)
	if store.Len() != 1 {
		t.Error("the message expired by the system clock")
	}

	// A Clock already set is kept.
	own := dsig.NewFakeClockAt(past)
	mine := &artifact.MemoryStore{Clock: own}
	newBinding(t, cfg, mine, 3)
	if mine.Clock != own {
		t.Error("New replaced the store's Clock")
	}
}

func TestResolutionServiceChecks(t *testing.T) {
	idp := &fakeIDP{}
	idp.key, idp.cert = keyPair(t)
	key, cert := keyPair(t)
	for name, opts := range map[string][]samlsp.Option{
		"no signing key": {artifact.ResolutionService(arsURL, 1)},
		"relative URL":   {samlsp.WithSigningKey(key, cert), artifact.ResolutionService("/saml/artifact", 1)},
	} {
		if _, err := samlsp.New(spEntityID, samlsp.StaticMetadata(idp.metadata()), opts...); err == nil {
			t.Errorf("%s: accepted", name)
		}
	}
}

// TestMemoryStoreMaxEntries checks that a full store refuses new messages,
// still replaces one it keeps, and takes new ones again once one is
// resolved; and that Encode reports a full store.
func TestMemoryStoreMaxEntries(t *testing.T) {
	s := &artifact.MemoryStore{MaxEntries: 2}
	ctx := context.Background()
	m := artifact.StoredMessage{XML: []byte("<x/>"), Recipient: idpEntityID, ExpiresAt: time.Now().Add(time.Minute)}
	for _, art := range []string{"a", "b", "b"} {
		if err := s.Save(ctx, art, m); err != nil {
			t.Fatalf("Save(%s): %v", art, err)
		}
	}
	if err := s.Save(ctx, "c", m); !errors.Is(err, artifact.ErrStoreFull) {
		t.Fatalf("Save into a full store: %v", err)
	}
	if got, _ := s.Take(ctx, "a", idpEntityID); got == nil {
		t.Fatal("Take(a) = nil")
	}
	if err := s.Save(ctx, "c", m); err != nil {
		t.Fatalf("Save after a Take: %v", err)
	}

	_, cfg, b, store, _ := setup(t)
	store.MaxEntries = 1
	if _, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b)); err != nil {
		t.Fatal(err)
	}
	if _, err := cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b)); !errors.Is(err, artifact.ErrStoreFull) {
		t.Errorf("AuthnRequest with a full store: %v", err)
	}
}
