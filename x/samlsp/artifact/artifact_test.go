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
	req := &saml.ArtifactResolve{
		ID: "id-resolve-1", Version: "2.0", IssueInstant: time.Now().UTC(),
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
	r := httptest.NewRequest(http.MethodPost, arsURL, strings.NewReader(body))
	r.Header.Set("Content-Type", "text/xml")
	w := httptest.NewRecorder()
	b.ServeHTTP(w, r)
	return w
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
	cfg, err := samlsp.New(samlsp.StaticMetadata(idp.metadata()), spEntityID,
		samlsp.WithKey(spKey, spCert), samlsp.SignAuthnRequests,
		samlsp.WithSLOURL("https://sp.example.com/saml/slo"),
		artifact.ResolutionService(arsURL, 3))
	if err != nil {
		t.Fatal(err)
	}
	store := artifact.NewMemoryStore()
	return idp, cfg, artifact.New(cfg, store, 3), store, spCert
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

	msg, err := cfg.LogoutRequest(t.Context(), saml.NameID{Value: "alice"}, "r", samlsp.WithCustomBinding(b))
	if err != nil {
		t.Fatal(err)
	}
	if got := artifactResponse(t, idp.resolve(t, b, msg.RedirectURL().Query().Get("SAMLart"), idpEntityID, idp.key, idp.cert), spCert); got == nil || got.Tag != "LogoutRequest" {
		t.Fatalf("got %v", got)
	}

	msg, err = cfg.LogoutResponse(t.Context(), &samlsp.LogoutRequest{ID: "id-idp-logout"}, samlsp.WithCustomBinding(b))
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
	if m, err := s.Take(ctx, "a"); m != nil || err != nil {
		t.Errorf("Take = %v, %v", m, err)
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
