package samlsp

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"errors"
	"fmt"
	"slices"

	"github.com/crewjam/saml"
)

// spMetadataOptions are the additions to the SP metadata.
type spMetadataOptions struct {
	attributeServices []saml.AttributeConsumingService
	organization      *saml.Organization
	contacts          []saml.ContactPerson
	nameIDFormats     []saml.NameIDFormat

	// nextSigningCerts and nextEncryptionCerts are published after the
	// current certificates (see WithNextSigningCertificates and
	// WithNextEncryptionCertificates).
	nextSigningCerts    []*x509.Certificate
	nextEncryptionCerts []*x509.Certificate
}

// RequestedAttribute is an attribute the SP asks the IdP to send, listed in
// the SP metadata (see WithRequestedAttributes).
type RequestedAttribute struct {
	// Name identifies the attribute, such as
	// "urn:oid:0.9.2342.19200300.100.1.3".
	Name string

	// NameFormat says how to read Name. If empty, it is
	// "urn:oasis:names:tc:SAML:2.0:attrname-format:uri" for a Name that is
	// a URI or an OID, as in the examples above, and is left out otherwise.
	NameFormat string

	// FriendlyName is an optional, human-readable form of Name, such as
	// "mail", which an IdP may show its administrators.
	FriendlyName string

	// Required says the SP cannot work without the attribute.
	Required bool
}

// uriNameFormat is the NameFormat of attributes named by URI.
const uriNameFormat = "urn:oasis:names:tc:SAML:2.0:attrname-format:uri"

func (a RequestedAttribute) saml() saml.RequestedAttribute {
	nameFormat := a.NameFormat
	if nameFormat == "" && isURIName(a.Name) {
		nameFormat = uriNameFormat
	}
	required := a.Required
	return saml.RequestedAttribute{
		Attribute: saml.Attribute{
			Name:         a.Name,
			NameFormat:   nameFormat,
			FriendlyName: a.FriendlyName,
		},
		IsRequired: &required,
	}
}

// isURIName reports whether name looks like an absolute URI, such as an
// "urn:oid:" OID or an http(s) URL.
func isURIName(name string) bool {
	for i, r := range name {
		switch {
		case r == ':':
			return i > 0
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z',
			i > 0 && (r >= '0' && r <= '9' || r == '+' || r == '-' || r == '.'):
		default:
			return false
		}
	}
	return false
}

// WithRequestedAttributes lists, in the SP metadata, the attributes the SP
// asks the IdP to send, in the AttributeConsumingService with index 1,
// which is the default (saml-metadata §2.4.4.1). serviceName names it, in
// English, as the schema requires. Many IdPs use the list to configure
// what they release to the SP.
//
// For more than one set of attributes, use WithAttributeConsumingService,
// and choose one per request with WithAttributeConsumingServiceIndex.
func WithRequestedAttributes(serviceName string, attrs ...RequestedAttribute) Option {
	isDefault := true
	svc := saml.AttributeConsumingService{
		Index:        1,
		IsDefault:    &isDefault,
		ServiceNames: []saml.LocalizedName{{Lang: "en", Value: serviceName}},
	}
	for _, a := range attrs {
		svc.RequestedAttributes = append(svc.RequestedAttributes, a.saml())
	}
	return WithAttributeConsumingService(svc)
}

// WithAttributeConsumingService adds svc to the SP metadata. Each must have
// a distinct Index, a ServiceName and at least one RequestedAttribute, and
// at most one may be the default.
func WithAttributeConsumingService(svc saml.AttributeConsumingService) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.spMetadata.attributeServices = append(c.spMetadata.attributeServices, svc)
	})
}

// WithOrganization sets the Organization of the SP metadata: who runs the
// SP. Many federations require it.
func WithOrganization(org saml.Organization) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.spMetadata.organization = &org })
}

// WithContactPerson adds a ContactPerson to the SP metadata. Its
// ContactType must be "technical", "support", "administrative", "billing"
// or "other". Many federations require a technical contact.
func WithContactPerson(contact saml.ContactPerson) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.spMetadata.contacts = append(c.spMetadata.contacts, contact)
	})
}

// WithNameIDFormats advertises, in the SP metadata, the NameID formats the
// SP accepts, in order of preference after the one it requests (see
// WithNameIDFormat), which is always listed first.
func WithNameIDFormats(formats ...saml.NameIDFormat) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.spMetadata.nameIDFormats = append(c.spMetadata.nameIDFormats, formats...)
	})
}

// WithNextSigningCertificates publishes certs in the SP metadata as
// signing keys too, after that of WithSigningKey, without signing with
// them: each is a KeyDescriptor with use="signing" (saml-metadata §2.4.1.1).
// An IdP that has the metadata accepts the SP's signatures, such as those
// of signed AuthnRequests and logout messages, by any of the keys it
// lists. Use it to announce a new signing certificate before switching
// WithSigningKey to it, so that IdPs that refresh the SP metadata already
// trust it when the rollover happens, or to keep publishing the old one
// for a while afterwards. Signed metadata (SignMetadata) is still signed
// by the key of WithSigningKey only.
//
// Each certificate must be for an RSA or ECDSA key, the keys that XML
// signatures are made with; New returns an error otherwise. A certificate
// that the metadata already publishes for signing, such as that of
// WithSigningKey, is not listed twice. See the package documentation for
// the whole rotation procedure.
func WithNextSigningCertificates(certs ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.spMetadata.nextSigningCerts = append(c.spMetadata.nextSigningCerts, certs...)
	})
}

// WithNextEncryptionCertificates publishes certs in the SP metadata as
// encryption keys too, after that of WithEncryptionKey: each is a
// KeyDescriptor with use="encryption" (saml-metadata §2.4.1.1), offering
// the same encryption methods. Use it to announce a new encryption key
// before switching WithEncryptionKey to it, or to keep publishing the old
// one for a while afterwards.
//
// The metadata gives an IdP no way to tell which encryption key is the
// current one, and IdPs differ in which they use: package saml's uses the
// first, others the last or any. So from the moment the metadata lists a
// certificate, the SP must be able to decrypt with its key: New returns an
// error unless each certificate is for the RSA key of WithEncryptionKey or
// of WithDecryptionKeys. Pass the next key to WithDecryptionKeys as soon
// as its certificate is published here. A certificate that the metadata
// already publishes for encryption, such as that of WithEncryptionKey, is
// not listed twice. See the package documentation for the whole rotation
// procedure.
func WithNextEncryptionCertificates(certs ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.spMetadata.nextEncryptionCerts = append(c.spMetadata.nextEncryptionCerts, certs...)
	})
}

// checkNextCertificates returns an error if a certificate of
// WithNextSigningCertificates cannot verify XML signatures, or one of
// WithNextEncryptionCertificates is not for a key the SP decrypts with.
func (o *spMetadataOptions) checkNextCertificates(encryptionKey *rsa.PrivateKey, decryptionKeys []*rsa.PrivateKey) error {
	for _, cert := range o.nextSigningCerts {
		if cert == nil {
			return errors.New("samlsp: WithNextSigningCertificates was given a nil certificate")
		}
		switch cert.PublicKey.(type) {
		case *rsa.PublicKey, *ecdsa.PublicKey:
		default:
			return fmt.Errorf("samlsp: the certificate %q of WithNextSigningCertificates is not for an RSA or ECDSA key", cert.Subject)
		}
	}
	for _, cert := range o.nextEncryptionCerts {
		if cert == nil {
			return errors.New("samlsp: WithNextEncryptionCertificates was given a nil certificate")
		}
		pub, ok := cert.PublicKey.(*rsa.PublicKey)
		if !ok {
			return fmt.Errorf("samlsp: the certificate %q of WithNextEncryptionCertificates is not for an RSA key", cert.Subject)
		}
		matches := func(key *rsa.PrivateKey) bool { return key != nil && pub.Equal(&key.PublicKey) }
		if !matches(encryptionKey) && !slices.ContainsFunc(decryptionKeys, matches) {
			return fmt.Errorf("samlsp: the certificate %q of WithNextEncryptionCertificates is not for the key of WithEncryptionKey or of WithDecryptionKeys; the SP could not decrypt assertions encrypted to it", cert.Subject)
		}
	}
	return nil
}

// check returns an error if the additions would make invalid metadata.
func (o *spMetadataOptions) check() error {
	indexes := map[int]bool{}
	defaults := 0
	for _, svc := range o.attributeServices {
		if svc.Index < 0 || svc.Index > 65535 {
			return fmt.Errorf("samlsp: AttributeConsumingService index %d is not between 0 and 65535", svc.Index)
		}
		if indexes[svc.Index] {
			return fmt.Errorf("samlsp: two AttributeConsumingServices have index %d", svc.Index)
		}
		indexes[svc.Index] = true
		if svc.IsDefault != nil && *svc.IsDefault {
			defaults++
		}
		if len(svc.ServiceNames) == 0 {
			return fmt.Errorf("samlsp: AttributeConsumingService %d has no ServiceName", svc.Index)
		}
		if len(svc.RequestedAttributes) == 0 {
			return fmt.Errorf("samlsp: AttributeConsumingService %d requests no attribute", svc.Index)
		}
		for _, a := range svc.RequestedAttributes {
			if a.Name == "" {
				return fmt.Errorf("samlsp: AttributeConsumingService %d requests an attribute with no Name", svc.Index)
			}
		}
	}
	if defaults > 1 {
		return errors.New("samlsp: more than one AttributeConsumingService is the default")
	}
	if org := o.organization; org != nil {
		if len(org.OrganizationNames) == 0 || len(org.OrganizationDisplayNames) == 0 || len(org.OrganizationURLs) == 0 {
			return errors.New("samlsp: an Organization needs an OrganizationName, an OrganizationDisplayName and an OrganizationURL")
		}
	}
	for _, cp := range o.contacts {
		switch cp.ContactType {
		case "technical", "support", "administrative", "billing", "other":
		default:
			return fmt.Errorf("samlsp: invalid ContactPerson type %q", cp.ContactType)
		}
	}
	return nil
}

// apply adds the additions to md, the SP metadata.
func (o *spMetadataOptions) apply(md *saml.EntityDescriptor) {
	sp := &md.SPSSODescriptors[0]
	sp.AttributeConsumingServices = append(sp.AttributeConsumingServices, o.attributeServices...)
	for _, f := range o.nameIDFormats {
		if !slices.Contains(sp.NameIDFormats, f) {
			sp.NameIDFormats = append(sp.NameIDFormats, f)
		}
	}
	md.Organization = o.organization
	md.ContactPersons = append(md.ContactPersons, o.contacts...)
	for _, cert := range o.nextSigningCerts {
		addKeyDescriptor(sp, saml.KeyDescriptor{
			Use: "signing",
			KeyInfo: saml.KeyInfo{X509Data: saml.X509Data{
				X509Certificates: []saml.X509Certificate{{Data: base64.StdEncoding.EncodeToString(cert.Raw)}},
			}},
		})
	}
	for _, cert := range o.nextEncryptionCerts {
		// Let package saml describe the key, so that it offers the same
		// encryption methods as that of WithEncryptionKey.
		desc := (&saml.ServiceProvider{EncryptionCertificate: cert, KeyOnlySigns: true}).Metadata()
		for _, kd := range desc.SPSSODescriptors[0].KeyDescriptors {
			if kd.Use == "encryption" {
				addKeyDescriptor(sp, kd)
			}
		}
	}
}

// addKeyDescriptor appends kd, which holds one certificate, to the
// KeyDescriptors of sp, unless one with the same use already holds the
// same certificate.
func addKeyDescriptor(sp *saml.SPSSODescriptor, kd saml.KeyDescriptor) {
	data := kd.KeyInfo.X509Data.X509Certificates[0].Data
	for _, have := range sp.KeyDescriptors {
		if have.Use != kd.Use {
			continue
		}
		for _, c := range have.KeyInfo.X509Data.X509Certificates {
			if c.Data == data {
				return
			}
		}
	}
	sp.KeyDescriptors = append(sp.KeyDescriptors, kd)
}
