package samlsp

import (
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
}
