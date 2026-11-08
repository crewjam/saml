package saml

import (
	"bytes"
	"encoding/xml"
	"errors"
	"fmt"

	"github.com/crewjam/saml/internal/xmlroundtrip"
)

// ParseServiceProviderMetadata parses the metadata of a service provider,
// as an identity provider needs it to register the SP: an EntityDescriptor
// with an SPSSODescriptor, or an EntitiesDescriptor aggregate (nested ones
// included) that holds exactly one such entity. It is the identity
// provider's counterpart of ParseMetadata in
// github.com/crewjam/saml/x/samlsp, which parses IdP metadata.
//
// The document is checked as every XML message is (it must survive a round
// trip through encoding/xml unchanged), but not its signature: to require
// one, verify data with VerifyMetadataSignature and parse what that
// returns. It returns an error if data is not metadata, describes no
// service provider, or describes more than one.
func ParseServiceProviderMetadata(data []byte) (*EntityDescriptor, error) {
	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, err
	}
	root, err := metadataRoot(data)
	if err != nil {
		return nil, err
	}
	if root.Space != metadataNamespace {
		return nil, fmt.Errorf("saml: %s is not SAML metadata", root.Local)
	}

	switch root.Local {
	case "EntityDescriptor":
		entity := &EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, err
		}
		if len(entity.SPSSODescriptors) == 0 {
			return nil, fmt.Errorf("saml: the metadata of %q has no SPSSODescriptor", entity.EntityID)
		}
		return entity, nil
	case "EntitiesDescriptor":
		entities := &EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		sps := serviceProviderEntities(entities)
		switch len(sps) {
		case 0:
			return nil, errors.New("saml: the metadata describes no service provider")
		case 1:
			return sps[0], nil
		default:
			return nil, fmt.Errorf("saml: the metadata describes %d service providers; register them one at a time", len(sps))
		}
	default:
		return nil, fmt.Errorf("saml: %s is not an EntityDescriptor or EntitiesDescriptor", root.Local)
	}
}

// metadataRoot returns the name of the root element of data.
func metadataRoot(data []byte) (xml.Name, error) {
	d := xml.NewDecoder(bytes.NewReader(data))
	for {
		tok, err := d.Token()
		if err != nil {
			return xml.Name{}, fmt.Errorf("saml: cannot read the metadata: %w", err)
		}
		if start, ok := tok.(xml.StartElement); ok {
			return start.Name, nil
		}
	}
}

// serviceProviderEntities returns the entities with an SPSSODescriptor in
// entities and in any EntitiesDescriptor nested in it.
func serviceProviderEntities(entities *EntitiesDescriptor) []*EntityDescriptor {
	var out []*EntityDescriptor
	for i := range entities.EntityDescriptors {
		if len(entities.EntityDescriptors[i].SPSSODescriptors) > 0 {
			out = append(out, &entities.EntityDescriptors[i])
		}
	}
	for i := range entities.EntitiesDescriptors {
		out = append(out, serviceProviderEntities(&entities.EntitiesDescriptors[i])...)
	}
	return out
}
