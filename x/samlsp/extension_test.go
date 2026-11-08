package samlsp_test

import (
	"context"
	"crypto/x509"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

// recordingBinding is a Binding that keeps the message it was given and
// sends the browser to its destination.
type recordingBinding struct {
	uri string
	got *samlsp.OutboundMessage
	xml string
}

func (b *recordingBinding) URI() string { return b.uri }

func (b *recordingBinding) Encode(_ context.Context, m *samlsp.OutboundMessage) (*samlsp.Message, error) {
	b.got = m
	el, err := m.Element()
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	b.xml, _ = doc.WriteToString()
	u, _ := url.Parse(m.Destination + "?msg=" + m.ID)
	return m.Redirect(u), nil
}

// withEndpoints returns ti's metadata with SSO and SLO endpoints for
// binding as well.
func withEndpoints(ti *testIDP, binding string) samlsp.MetadataFunc {
	return func(context.Context) (*saml.EntityDescriptor, error) {
		md := ti.idp.Metadata()
		d := &md.IDPSSODescriptors[0]
		d.SingleSignOnServices = append(d.SingleSignOnServices, saml.Endpoint{Binding: binding, Location: "https://idp.example.com/sso-custom"})
		d.SingleLogoutServices = append(d.SingleLogoutServices, saml.Endpoint{Binding: binding, Location: "https://idp.example.com/slo-custom"})
		return md, nil
	}
}

func TestCustomBinding(t *testing.T) {
	const uri = "urn:example:binding"
	ti := newTestIDP(t)
	cfg := newTestConfigWithIDP(t, ti, withEndpoints(ti, uri), samlsp.SignAuthnRequests)
	b := &recordingBinding{uri: uri}

	msg, err := cfg.AuthnRequest(t.Context(), "relay", samlsp.WithCustomBinding(b), samlsp.WithScriptNonce("n"))
	if err != nil {
		t.Fatal(err)
	}
	if msg.Binding != uri || msg.ID != b.got.ID || msg.RedirectURL().String() != "https://idp.example.com/sso-custom?msg="+msg.ID {
		t.Errorf("message %+v", msg)
	}
	if b.got.Destination != "https://idp.example.com/sso-custom" || b.got.Param != "SAMLRequest" ||
		b.got.RelayState != "relay" || b.got.ScriptNonce != "n" {
		t.Errorf("outbound %+v", b.got)
	}
	if !strings.Contains(b.xml, `Destination="https://idp.example.com/sso-custom"`) || !strings.Contains(b.xml, "SignatureValue") {
		t.Errorf("AuthnRequest not addressed or signed: %s", b.xml)
	}

	// An IdP without an endpoint for the binding.
	plain := newTestConfig(t, ti)
	if _, err := plain.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(b)); !errors.Is(err, samlsp.ErrNoEndpoint) {
		t.Errorf("err = %v, want ErrNoEndpoint", err)
	}

	// Respond: a Message that writes what the binding wants.
	writer := bindingFunc{uri: uri, encode: func(m *samlsp.OutboundMessage) *samlsp.Message {
		return m.Respond(func(w http.ResponseWriter) { w.WriteHeader(http.StatusTeapot) })
	}}
	msg, err = cfg.AuthnRequest(t.Context(), "r", samlsp.WithCustomBinding(writer))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	msg.Write(w)
	if w.Code != http.StatusTeapot {
		t.Errorf("Respond wrote %d", w.Code)
	}
}

type bindingFunc struct {
	uri    string
	encode func(*samlsp.OutboundMessage) *samlsp.Message
}

func (b bindingFunc) URI() string { return b.uri }
func (b bindingFunc) Encode(_ context.Context, m *samlsp.OutboundMessage) (*samlsp.Message, error) {
	return b.encode(m), nil
}

func TestWithMetadataHook(t *testing.T) {
	ti := newTestIDP(t)
	key, cert := newKeyPair(t, "sp")
	cfg, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(key, cert), samlsp.SignMetadata,
		samlsp.WithMetadata(func(md *saml.EntityDescriptor) {
			md.SPSSODescriptors[0].ArtifactResolutionServices = []saml.IndexedEndpoint{
				{Binding: saml.SOAPBinding, Location: "https://sp.example.com/saml/artifact", Index: 1},
			}
		}))
	if err != nil {
		t.Fatal(err)
	}
	if ars := cfg.Metadata(t.Context()).SPSSODescriptors[0].ArtifactResolutionServices; len(ars) != 1 {
		t.Fatalf("hook not applied: %+v", ars)
	}
	// The signature covers what the hook added.
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	verified, err := vc.Validate(doc.Root())
	if err != nil {
		t.Fatal(err)
	}
	if verified.FindElement("./SPSSODescriptor/ArtifactResolutionService") == nil {
		t.Error("the signed metadata lacks the hook's addition")
	}
}

func TestSignElementAndServiceProvider(t *testing.T) {
	ti := newTestIDP(t)
	key, cert := newKeyPair(t, "sp")
	cfg, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(key, cert),
		samlsp.WithSignatureMethod(dsig.RSASHA512SignatureMethod))
	if err != nil {
		t.Fatal(err)
	}
	el := etree.NewElement("Thing")
	el.CreateAttr("ID", "id-thing")
	el.CreateElement("Issuer").SetText("me")
	el.CreateElement("Body")
	signed, err := cfg.SignElement(el)
	if err != nil {
		t.Fatal(err)
	}
	if el.FindElement("./Signature") != nil {
		t.Error("SignElement modified its argument")
	}
	if c := signed.ChildElements(); len(c) != 3 || c[1].Tag != "Signature" {
		t.Error("the Signature is not right after the Issuer")
	}
	// As received: serialized and parsed again.
	doc := etree.NewDocument()
	doc.SetRoot(signed)
	buf, _ := doc.WriteToBytes()
	reparsed := etree.NewDocument()
	if err := reparsed.ReadFromBytes(buf); err != nil {
		t.Fatal(err)
	}
	signed = reparsed.Root()
	if m := signed.FindElement("./Signature/SignedInfo/SignatureMethod"); m == nil || m.SelectAttrValue("Algorithm", "") != dsig.RSASHA512SignatureMethod {
		t.Error("not signed with the configured method")
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	if _, err := vc.Validate(signed); err != nil {
		t.Errorf("signature: %v", err)
	}

	sp, err := cfg.ServiceProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if sp.IDPMetadata == nil || sp.EntityID != spEntityID || sp.Key == nil {
		t.Errorf("ServiceProvider = %+v", sp)
	}

	noKey, _ := samlsp.New(spEntityID, staticIDP(ti))
	if _, err := noKey.SignElement(el); err == nil {
		t.Error("SignElement without a key")
	}
}

// Changing the slices of a ServiceProvider does not change the Config, or
// the ServiceProvider of the next call.
func TestServiceProviderSharesNoSlices(t *testing.T) {
	ti := newTestIDP(t)
	key, cert := newKeyPair(t, "sp")
	decryptionKey, _ := newKeyPair(t, "old")
	_, intermediateCert := newKeyPair(t, "intermediate")
	cfg, err := samlsp.New(spEntityID, staticIDP(ti),
		samlsp.WithSigningKey(key, cert, intermediateCert), samlsp.WithDecryptionKeys(decryptionKey))
	if err != nil {
		t.Fatal(err)
	}
	sp, err := cfg.ServiceProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	sp.Intermediates[0] = nil
	sp.DecryptionKeys[0] = nil
	again, err := cfg.ServiceProvider(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if again.Intermediates[0] != intermediateCert || again.DecryptionKeys[0] != decryptionKey {
		t.Error("changing a ServiceProvider's slices changed the Config")
	}
}

// New refuses a WithSigningKey whose certificate is for another key.
func TestSigningKeyCertificateMismatch(t *testing.T) {
	ti := newTestIDP(t)
	key, _ := newKeyPair(t, "sp")
	_, other := newKeyPair(t, "other")
	if _, err := samlsp.New(spEntityID, staticIDP(ti), samlsp.WithSigningKey(key, other)); err == nil {
		t.Error("New accepted a signing certificate for another key")
	}
}
