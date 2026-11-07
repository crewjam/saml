package samlidp

import (
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"

	"github.com/crewjam/saml/internal/xmlroundtrip"

	"github.com/crewjam/saml"
)

func randomBytes(n int) []byte {
	rv := make([]byte, n)
	if _, err := io.ReadFull(saml.RandReader, rv); err != nil {
		panic(err)
	}
	return rv
}

// MaxServiceMetadataSize is the size in bytes of the largest service
// provider metadata document the service endpoints read. A larger request
// body is refused rather than read into memory in full.
var MaxServiceMetadataSize int64 = 10 << 20

// getSPMetadata reads service provider metadata from r: an EntityDescriptor,
// or an EntitiesDescriptor holding exactly one entity with an
// SPSSODescriptor. With several, it cannot tell which one is meant.
func getSPMetadata(r io.Reader) (*saml.EntityDescriptor, error) {
	return getVerifiedSPMetadata(r, nil)
}

// getVerifiedSPMetadata is getSPMetadata, except that when certs is not
// empty the root element of the metadata must carry a valid enveloped XML
// signature made with one of certs, and only the content the signature
// covers is parsed (see saml.VerifyMetadataSignature). Unsigned metadata is
// then refused.
func getVerifiedSPMetadata(r io.Reader, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	data, err := readSPMetadata(r)
	if err != nil {
		return nil, err
	}
	return verifiedSPMetadata(data, certs)
}

// readSPMetadata reads a metadata document from r, at most
// MaxServiceMetadataSize bytes.
func readSPMetadata(r io.Reader) ([]byte, error) {
	limit := MaxServiceMetadataSize
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("metadata is larger than %d bytes (MaxServiceMetadataSize)", limit)
	}
	return data, nil
}

// verifiedSPMetadata parses the metadata document data as
// getVerifiedSPMetadata does.
func verifiedSPMetadata(data []byte, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	if len(certs) > 0 {
		var err error
		if data, err = saml.VerifyMetadataSignature(data, certs); err != nil {
			return nil, err
		}
	}
	return parseSPMetadata(data)
}

// parseSPMetadata parses the metadata document data as getSPMetadata does,
// without checking any signature.
func parseSPMetadata(data []byte) (*saml.EntityDescriptor, error) {
	if err := xmlroundtrip.Validate(data); err != nil {
		return nil, err
	}

	spMetadata := &saml.EntityDescriptor{}
	if err := xml.Unmarshal(data, spMetadata); err != nil {
		if err.Error() != "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			return nil, err
		}
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		sps := spEntities(entities)
		switch len(sps) {
		case 0:
			return nil, errors.New("metadata contained no service provider metadata")
		case 1:
			return sps[0], nil
		default:
			return nil, fmt.Errorf("metadata holds %d entities with an SPSSODescriptor; register them one at a time", len(sps))
		}
	}
	return spMetadata, nil
}

// spEntities returns the entities with an SPSSODescriptor in entities and
// in any EntitiesDescriptor nested in it.
func spEntities(entities *saml.EntitiesDescriptor) []*saml.EntityDescriptor {
	var rv []*saml.EntityDescriptor
	for i := range entities.EntityDescriptors {
		if len(entities.EntityDescriptors[i].SPSSODescriptors) > 0 {
			rv = append(rv, &entities.EntityDescriptors[i])
		}
	}
	for i := range entities.EntitiesDescriptors {
		rv = append(rv, spEntities(&entities.EntitiesDescriptors[i])...)
	}
	return rv
}
