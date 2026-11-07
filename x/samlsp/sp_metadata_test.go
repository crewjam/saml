package samlsp_test

import (
	"crypto/x509"
	"encoding/xml"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/x/samlsp"
)

var testOrganization = saml.Organization{
	OrganizationNames:        []saml.LocalizedName{{Lang: "en", Value: "Example Inc."}},
	OrganizationDisplayNames: []saml.LocalizedName{{Lang: "en", Value: "Example"}},
	OrganizationURLs:         []saml.LocalizedURI{{Lang: "en", Value: "https://example.com"}},
}

var testContact = saml.ContactPerson{ContactType: "technical", EmailAddresses: []string{"mailto:saml@example.com"}}

func spMetadataOptions() []samlsp.Option {
	return []samlsp.Option{
		samlsp.WithRequestedAttributes("Example",
			samlsp.RequestedAttribute{Name: "urn:oid:0.9.2342.19200300.100.1.3", FriendlyName: "mail", Required: true},
			samlsp.RequestedAttribute{Name: "displayName"}),
		samlsp.WithAttributeConsumingService(saml.AttributeConsumingService{
			Index:               2,
			ServiceNames:        []saml.LocalizedName{{Lang: "en", Value: "Groups"}},
			RequestedAttributes: []saml.RequestedAttribute{{Attribute: saml.Attribute{Name: "memberOf"}}},
		}),
		samlsp.WithOrganization(testOrganization),
		samlsp.WithContactPerson(testContact),
		samlsp.WithContactPerson(saml.ContactPerson{ContactType: "support", EmailAddresses: []string{"mailto:help@example.com"}}),
		samlsp.WithNameIDFormats(saml.PersistentNameIDFormat, saml.TransientNameIDFormat),
	}
}

func TestSPMetadataAdditions(t *testing.T) {
	ti := newTestIDP(t)
	cfg := newTestConfig(t, ti, spMetadataOptions()...)

	// Through ServeMetadata, as the IdP reads it.
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))
	var md saml.EntityDescriptor
	if err := xml.Unmarshal(w.Body.Bytes(), &md); err != nil {
		t.Fatal(err)
	}
	sp := md.SPSSODescriptors[0]

	if n := len(sp.AttributeConsumingServices); n != 2 {
		t.Fatalf("%d AttributeConsumingServices", n)
	}
	first := sp.AttributeConsumingServices[0]
	if first.Index != 1 || first.IsDefault == nil || !*first.IsDefault || first.ServiceNames[0].Value != "Example" {
		t.Errorf("first service = %+v", first)
	}
	mail, name := first.RequestedAttributes[0], first.RequestedAttributes[1]
	if mail.NameFormat != "urn:oasis:names:tc:SAML:2.0:attrname-format:uri" || mail.IsRequired == nil || !*mail.IsRequired {
		t.Errorf("mail = %+v", mail)
	}
	if name.NameFormat != "" || name.IsRequired == nil || *name.IsRequired {
		t.Errorf("displayName = %+v", name)
	}
	if md.Organization == nil || md.Organization.OrganizationNames[0].Value != "Example Inc." {
		t.Errorf("Organization = %+v", md.Organization)
	}
	if len(md.ContactPersons) != 2 || md.ContactPersons[1].ContactType != "support" {
		t.Errorf("ContactPersons = %+v", md.ContactPersons)
	}
	// The requested format first (transient by default), then the others,
	// once each.
	if f := sp.NameIDFormats; len(f) != 2 || f[0] != saml.TransientNameIDFormat || f[1] != saml.PersistentNameIDFormat {
		t.Errorf("NameIDFormats = %v", f)
	}
}

func TestSPMetadataAdditionsSigned(t *testing.T) {
	ti := newTestIDP(t)
	key, cert := newKeyPair(t, "sp")
	opts := append(spMetadataOptions(), samlsp.WithKey(key, cert), samlsp.SignMetadata)
	cfg, err := samlsp.New(staticIDP(ti), spEntityID, opts...)
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	cfg.ServeMetadata(w, httptest.NewRequest(http.MethodGet, spEntityID, nil))

	doc := etree.NewDocument()
	if err := doc.ReadFromBytes(w.Body.Bytes()); err != nil {
		t.Fatal(err)
	}
	vc := dsig.NewDefaultValidationContext(&dsig.MemoryX509CertificateStore{Roots: []*x509.Certificate{cert}})
	verified, err := vc.Validate(doc.Root())
	if err != nil {
		t.Fatalf("signature: %v", err)
	}
	// The signature covers the additions.
	for _, path := range []string{"./Organization", "./ContactPerson", "./SPSSODescriptor/AttributeConsumingService"} {
		if verified.FindElement(path) == nil {
			t.Errorf("%s is not in the signed metadata", path)
		}
	}
}

func TestSPMetadataAdditionsErrors(t *testing.T) {
	ti := newTestIDP(t)
	yes := true
	svc := func(index int, isDefault bool) samlsp.Option {
		s := saml.AttributeConsumingService{
			Index:               index,
			ServiceNames:        []saml.LocalizedName{{Lang: "en", Value: "x"}},
			RequestedAttributes: []saml.RequestedAttribute{{Attribute: saml.Attribute{Name: "a"}}},
		}
		if isDefault {
			s.IsDefault = &yes
		}
		return samlsp.WithAttributeConsumingService(s)
	}
	for name, opts := range map[string][]samlsp.Option{
		"duplicate index": {svc(1, false), svc(1, false)},
		"two defaults":    {svc(1, true), svc(2, true)},
		"no attributes":   {samlsp.WithRequestedAttributes("x")},
		"no service name": {samlsp.WithAttributeConsumingService(saml.AttributeConsumingService{Index: 3, RequestedAttributes: []saml.RequestedAttribute{{Attribute: saml.Attribute{Name: "a"}}}})},
		"empty name":      {samlsp.WithRequestedAttributes("x", samlsp.RequestedAttribute{})},
		"bad contact":     {samlsp.WithContactPerson(saml.ContactPerson{ContactType: "sales"})},
		"thin org":        {samlsp.WithOrganization(saml.Organization{OrganizationNames: testOrganization.OrganizationNames})},
	} {
		if _, err := samlsp.New(staticIDP(ti), spEntityID, opts...); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}
