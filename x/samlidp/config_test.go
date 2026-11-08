package samlidp_test

import (
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlidp"
	"github.com/crewjam/saml/x/samlsp"
)

func TestNew(t *testing.T) {
	keys(t)
	sps := samlidp.StaticServiceProviders()
	key := samlidp.WithSigningKey(idpKey, idpCert)
	for _, tc := range []struct {
		name     string
		entityID string
		sps      samlidp.ServiceProviderFunc
		opts     []samlidp.Option
	}{
		{"no entity ID", "", sps, []samlidp.Option{key}},
		{"no service providers", idpEntityID, nil, []samlidp.Option{key}},
		{"no key", idpEntityID, sps, nil},
		{"wrong certificate", idpEntityID, sps, []samlidp.Option{samlidp.WithSigningKey(idpKey, spCert)}},
		{"URN without SSO URL", "urn:example:idp", sps, []samlidp.Option{key}},
		{"relative SSO URL", idpEntityID, sps, []samlidp.Option{key, samlidp.WithSSOURL("/sso")}},
		{"SHA-1", idpEntityID, sps, []samlidp.Option{key, samlidp.WithSignatureMethod("http://www.w3.org/2000/09/xmldsig#rsa-sha1")}},
		{"ECDSA method for RSA key", idpEntityID, sps, []samlidp.Option{key, samlidp.WithSignatureMethod("http://www.w3.org/2001/04/xmldsig-more#ecdsa-sha256")}},
	} {
		if _, err := samlidp.New(tc.entityID, tc.sps, tc.opts...); err == nil {
			t.Errorf("%s: no error", tc.name)
		}
	}

	c, err := samlidp.New("urn:example:idp", sps, key, samlidp.WithSSOURL("https://idp.example.com/login/saml"))
	if err != nil {
		t.Fatal(err)
	}
	if c.EntityID() != "urn:example:idp" || c.SSOURL() != "https://idp.example.com/login/saml" || c.SSOPath() != "/login/saml" || c.MetadataPath() != "" {
		t.Errorf("got %q %q %q %q", c.EntityID(), c.SSOURL(), c.SSOPath(), c.MetadataPath())
	}
	c, err = samlidp.New(idpEntityID, sps, key)
	if err != nil {
		t.Fatal(err)
	}
	if c.SSOURL() != "https://idp.example.com/saml/sso" || c.MetadataPath() != "/saml/metadata" {
		t.Errorf("got %q %q", c.SSOURL(), c.MetadataPath())
	}
}

func TestMetadata(t *testing.T) {
	keys(t)
	c, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert),
		samlidp.WithNameIDFormats(saml.PersistentNameIDFormat, saml.EmailAddressNameIDFormat),
		samlidp.WithNextSigningCertificates(spCert),
		samlidp.WithMetadata(func(md *saml.EntityDescriptor) {
			md.IDPSSODescriptors[0].SingleLogoutServices = []saml.Endpoint{{Binding: saml.HTTPRedirectBinding, Location: "https://idp.example.com/saml/slo"}}
		}),
		samlidp.SignMetadata)
	if err != nil {
		t.Fatal(err)
	}
	md := c.Metadata()
	if md.EntityID != idpEntityID || len(md.IDPSSODescriptors) != 1 {
		t.Fatalf("got %+v", md)
	}
	d := md.IDPSSODescriptors[0]
	for _, k := range d.KeyDescriptors {
		if k.Use != "signing" {
			t.Errorf("key descriptor for %q: the IdP decrypts nothing", k.Use)
		}
	}
	if len(d.KeyDescriptors) != 2 {
		t.Errorf("%d key descriptors, want the signing certificate and the next one", len(d.KeyDescriptors))
	}
	if len(d.NameIDFormats) != 2 || d.NameIDFormats[0] != saml.PersistentNameIDFormat {
		t.Errorf("NameIDFormats = %v", d.NameIDFormats)
	}
	if len(d.SingleSignOnServices) != 2 || d.SingleSignOnServices[0].Location != c.SSOURL() {
		t.Errorf("SingleSignOnServices = %+v", d.SingleSignOnServices)
	}
	if len(d.SingleLogoutServices) != 1 {
		t.Errorf("WithMetadata was not applied")
	}

	rec := httptest.NewRecorder()
	c.ServeMetadata(rec, httptest.NewRequest(http.MethodGet, c.MetadataPath(), http.NoBody))
	if ct := rec.Header().Get("Content-Type"); ct != "application/samlmetadata+xml" {
		t.Errorf("Content-Type = %q", ct)
	}
	signed, err := saml.VerifyMetadataSignature(rec.Body.Bytes(), []*x509.Certificate{idpCert})
	if err != nil {
		t.Fatalf("the signature does not verify: %v", err)
	}
	// An SP takes it.
	parsed, err := samlsp.ParseMetadata(signed)
	if err != nil {
		t.Fatal(err)
	}
	if parsed.EntityID != idpEntityID {
		t.Errorf("EntityID = %q", parsed.EntityID)
	}

	// Unsigned when asked per call without SignMetadata.
	c, err = samlidp.New(idpEntityID, samlidp.StaticServiceProviders(), samlidp.WithSigningKey(idpKey, idpCert))
	if err != nil {
		t.Fatal(err)
	}
	buf, err := c.MetadataXML()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(buf), "Signature") {
		t.Error("unsigned metadata has a signature")
	}
	if _, err := saml.VerifyMetadataSignature(buf, []*x509.Certificate{idpCert}); err == nil {
		t.Error("unsigned metadata verified")
	}
}

func TestParseMetadata(t *testing.T) {
	p := newPair(t, nil, nil)
	ctx := context.Background()
	data, err := p.sp.MetadataXML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	md, err := samlidp.ParseMetadata(data)
	if err != nil {
		t.Fatal(err)
	}
	if md.EntityID != spEntityID {
		t.Fatalf("EntityID = %q", md.EntityID)
	}

	// An aggregate.
	other := *p.sp.Metadata(ctx)
	other.EntityID = "https://other.example.com"
	agg, err := xml.Marshal(saml.EntitiesDescriptor{EntityDescriptors: []saml.EntityDescriptor{*p.sp.Metadata(ctx), other, *p.idp.Metadata()}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := samlidp.ParseMetadata(agg); err == nil || !strings.Contains(err.Error(), "WithServiceProviderEntityID") {
		t.Fatalf("aggregate of two SPs: got %v", err)
	}
	md, err = samlidp.ParseMetadata(agg, samlidp.WithServiceProviderEntityID("https://other.example.com"))
	if err != nil || md.EntityID != "https://other.example.com" {
		t.Fatalf("got %v, %v", md, err)
	}
	if _, err := samlidp.ParseMetadata(agg, samlidp.WithServiceProviderEntityID(idpEntityID)); err == nil {
		t.Fatal("chose an IdP")
	}

	// Signed.
	if _, err := samlidp.ParseMetadata(data, samlidp.WithMetadataSigners(spCert)); err == nil {
		t.Fatal("unsigned metadata passed WithMetadataSigners")
	}
	signedSP, err := samlsp.New(spEntityID, nil, samlsp.WithSigningKey(spKey, spCert), samlsp.SignMetadata)
	if err != nil {
		t.Fatal(err)
	}
	data, err = signedSP.MetadataXML(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := samlidp.ParseMetadata(data, samlidp.WithMetadataSigners(spCert)); err != nil {
		t.Fatal(err)
	}

	for _, bad := range []string{"", "<x/>", "<EntityDescriptor xmlns='urn:oasis:names:tc:SAML:2.0:metadata' entityID='a'/>"} {
		if _, err := samlidp.ParseMetadata([]byte(bad)); err == nil {
			t.Errorf("%q: no error", bad)
		}
	}
}

func TestServiceProviderFunc(t *testing.T) {
	p := newPair(t, nil, nil)
	ctx := context.Background()
	for _, tc := range []struct {
		name    string
		fn      samlidp.ServiceProviderFunc
		unknown bool
	}{
		{"not found", func(context.Context, string) (*saml.EntityDescriptor, error) { return nil, errors.New("database down") }, false},
		{"os.ErrNotExist", func(context.Context, string) (*saml.EntityDescriptor, error) { return nil, errNotExist }, true},
		{"nil", func(context.Context, string) (*saml.EntityDescriptor, error) { return nil, nil }, true},
		{"another SP", func(context.Context, string) (*saml.EntityDescriptor, error) {
			md := *p.sp.Metadata(ctx)
			md.EntityID = "https://other.example.com"
			return &md, nil
		}, false},
	} {
		c, err := samlidp.New(idpEntityID, tc.fn, samlidp.WithSigningKey(idpKey, idpCert))
		if err != nil {
			t.Fatal(err)
		}
		msg, err := p.sp.AuthnRequest(ctx, "")
		if err != nil {
			t.Fatal(err)
		}
		_, err = c.ParseAuthnRequest(ctx, browserRequest(t, msg))
		if err == nil {
			t.Errorf("%s: no error", tc.name)
			continue
		}
		if got := errors.Is(err, samlidp.ErrUnknownServiceProvider); got != tc.unknown {
			t.Errorf("%s: %v matches ErrUnknownServiceProvider: %v", tc.name, err, got)
		}
	}
}

func TestMessage(t *testing.T) {
	p := newPair(t, nil, nil)
	_, req, err := p.parse(t)
	if err != nil {
		t.Fatal(err)
	}
	msg, err := p.idp.Response(context.Background(), req, testSubject, samlidp.WithScriptNonce("n0nce"),
		samlidp.WithSubjectAddress("192.0.2.1"))
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	msg.Write(rec)
	h := rec.Header()
	if !strings.Contains(h.Get("Content-Security-Policy"), "script-src 'sha256-") || h.Get("Cache-Control") != "no-cache, no-store" {
		t.Errorf("headers %v", h)
	}
	body := rec.Body.String()
	if !strings.Contains(body, `nonce="n0nce"`) || !strings.Contains(body, `action="`+p.sp.ACSURL()+`"`) {
		t.Errorf("body %s", body)
	}
	fields := msg.FormValues()
	if fields["RelayState"] != "rs" || fields["SAMLResponse"] == "" || len(fields) != 2 {
		t.Errorf("FormValues = %v", fields)
	}
	if msg.ID == "" || msg.Binding != saml.HTTPPostBinding {
		t.Errorf("got %+v", msg)
	}
	a, err := p.deliver(t, msg, samlsp.WithRequestID(req.ID))
	if err != nil {
		t.Fatal(err)
	}
	if addr := a.Raw.Subject.SubjectConfirmations[0].SubjectConfirmationData.Address; addr != "192.0.2.1" {
		t.Errorf("Address = %q", addr)
	}
}

var errNotExist = errors.Join(errors.New("no such row"), fs.ErrNotExist)

// TestIdentityProviderIsNew changes the slices of one IdentityProvider and
// checks that the next does not see it: each call may change its own.
func TestIdentityProviderIsNew(t *testing.T) {
	keys(t)
	c, err := samlidp.New(idpEntityID, samlidp.StaticServiceProviders(),
		samlidp.WithSigningKey(idpKey, idpCert, spCert),
		samlidp.WithNextSigningCertificates(spCert),
		samlidp.WithNameIDFormats(saml.PersistentNameIDFormat, saml.TransientNameIDFormat))
	if err != nil {
		t.Fatal(err)
	}
	idp := c.IdentityProvider()
	idp.NameIDFormats[0] = saml.EmailAddressNameIDFormat
	idp.NameIDFormats = append(idp.NameIDFormats[:1], saml.UnspecifiedNameIDFormat)
	idp.Intermediates[0] = idpCert
	idp.ExtraCertificates[0] = idpCert

	idp = c.IdentityProvider()
	if len(idp.NameIDFormats) != 2 || idp.NameIDFormats[0] != saml.PersistentNameIDFormat || idp.NameIDFormats[1] != saml.TransientNameIDFormat {
		t.Errorf("NameIDFormats = %v", idp.NameIDFormats)
	}
	if idp.Intermediates[0] != spCert || idp.ExtraCertificates[0] != spCert {
		t.Error("the certificates were changed")
	}
}

// TestNilOptions passes nil options, which are skipped.
func TestNilOptions(t *testing.T) {
	p := newPair(t, []samlidp.Option{nil}, nil)
	ctx := context.Background()
	msg, err := p.sp.AuthnRequest(ctx, "")
	if err != nil {
		t.Fatal(err)
	}
	req, err := p.idp.ParseAuthnRequest(ctx, browserRequest(t, msg), nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.Response(ctx, req, testSubject, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := p.idp.IDPInitiated(ctx, spEntityID, "", nil); err != nil {
		t.Fatal(err)
	}
}
