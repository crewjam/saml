package samlsp

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"

	xrv "github.com/mattermost/xml-roundtrip-validator"

	"github.com/crewjam/saml/logger"

	"github.com/crewjam/saml"
)

// ParseMetadata parses arbitrary SAML IDP metadata.
//
// Note: this is needed because IDP metadata is sometimes wrapped in
// an <EntitiesDescriptor>, and sometimes the top level element is an
// <EntityDescriptor>.
//
// An <EntitiesDescriptor> must hold exactly one entity with an
// IDPSSODescriptor (nested <EntitiesDescriptor> elements included), which
// is returned: ParseMetadata cannot tell which of several IDPs the caller
// means to trust. Use ParseMetadataByEntityID to pick one out of an
// aggregate.
//
// ParseMetadata does not check a signature on the metadata, so the
// metadata must come from a source the caller trusts. See
// ParseSignedMetadata.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	entity := &saml.EntityDescriptor{}

	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	err := xml.Unmarshal(data, entity)

	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		// Unmarshal the whole aggregate first, so that malformed metadata is
		// rejected wherever the error is.
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		if n := countIDPEntities(entities); n > 1 {
			return nil, fmt.Errorf("metadata holds %d entities with an IDPSSODescriptor; use ParseMetadataByEntityID to choose one", n)
		}
		entity, err := firstIDPEntity(data)
		if err != nil {
			return nil, err
		}
		if entity == nil {
			return nil, errors.New("no entity found with IDPSSODescriptor")
		}
		return entity, nil
	}
	if err != nil {
		return nil, err
	}
	return entity, nil
}

// ParseMetadataByEntityID parses SAML metadata and returns the
// EntityDescriptor whose entityID is entityID.
//
// The metadata may be a single <EntityDescriptor> or an <EntitiesDescriptor>
// aggregate, such as the metadata published by a federation (e.g. eduGAIN or
// InCommon). Nested <EntitiesDescriptor> elements are searched too. Unlike
// ParseMetadata, which returns the first entity with an IDPSSODescriptor, this
// lets the caller pick a specific IDP out of an aggregate.
//
// It returns an error if no entity with that entityID is found.
func ParseMetadataByEntityID(data []byte, entityID string) (*saml.EntityDescriptor, error) {
	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	root, err := metadataRootElement(data)
	if err != nil {
		return nil, err
	}

	if root.Local == "EntitiesDescriptor" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}
		if entity := findEntityByID(entities, entityID); entity != nil {
			return entity, nil
		}
	} else {
		entity := &saml.EntityDescriptor{}
		if err := xml.Unmarshal(data, entity); err != nil {
			return nil, err
		}
		if entity.EntityID == entityID {
			return entity, nil
		}
	}
	return nil, fmt.Errorf("no entity found with entityID %q", entityID)
}

// countIDPEntities returns the number of entities with an IDPSSODescriptor
// in entities and in any EntitiesDescriptor nested in it.
func countIDPEntities(entities *saml.EntitiesDescriptor) int {
	n := 0
	for _, e := range entities.EntityDescriptors {
		if len(e.IDPSSODescriptors) > 0 {
			n++
		}
	}
	for i := range entities.EntitiesDescriptors {
		n += countIDPEntities(&entities.EntitiesDescriptors[i])
	}
	return n
}

// ParseSignedMetadata is ParseMetadata for metadata whose root element must
// carry a valid enveloped XML signature made with one of certs, the IDP's
// (or its federation's) metadata signing certificates, obtained from a
// source the caller trusts. Only the content the signature covers is
// parsed. See saml.VerifyMetadataSignature.
func ParseSignedMetadata(data []byte, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	signed, err := saml.VerifyMetadataSignature(data, certs)
	if err != nil {
		return nil, err
	}
	return ParseMetadata(signed)
}

// ParseSignedMetadataByEntityID is ParseMetadataByEntityID for metadata
// whose root element must carry a valid enveloped XML signature made with
// one of certs. See ParseSignedMetadata.
func ParseSignedMetadataByEntityID(data []byte, entityID string, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	signed, err := saml.VerifyMetadataSignature(data, certs)
	if err != nil {
		return nil, err
	}
	return ParseMetadataByEntityID(signed, entityID)
}

// metadataRootElement returns the name of the root element of data.
func metadataRootElement(data []byte) (xml.Name, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err != nil {
			return xml.Name{}, err
		}
		if start, ok := token.(xml.StartElement); ok {
			return start.Name, nil
		}
	}
}

// findEntityByID returns the first EntityDescriptor in entities, or in any
// EntitiesDescriptor nested in it, whose entityID is entityID.
func findEntityByID(entities *saml.EntitiesDescriptor, entityID string) *saml.EntityDescriptor {
	for i := range entities.EntityDescriptors {
		if entities.EntityDescriptors[i].EntityID == entityID {
			return &entities.EntityDescriptors[i]
		}
	}
	for i := range entities.EntitiesDescriptors {
		if entity := findEntityByID(&entities.EntitiesDescriptors[i], entityID); entity != nil {
			return entity
		}
	}
	return nil
}

// metadataNamespace is the SAML 2.0 metadata namespace.
const metadataNamespace = "urn:oasis:names:tc:SAML:2.0:metadata"

// firstIDPEntity returns the first <EntityDescriptor> with an
// IDPSSODescriptor in the <EntitiesDescriptor> aggregate data, or in any
// <EntitiesDescriptor> nested in it, in document order. It returns nil if
// there is none.
//
// EntitiesDescriptor keeps nested aggregates and entities in separate
// slices, which loses their relative order, so data is walked token by
// token instead.
func firstIDPEntity(data []byte) (*saml.EntityDescriptor, error) {
	decoder := xml.NewDecoder(bytes.NewReader(data))
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		start, ok := token.(xml.StartElement)
		if !ok {
			continue
		}
		if start.Name.Space != metadataNamespace {
			if err := decoder.Skip(); err != nil {
				return nil, err
			}
			continue
		}
		switch start.Name.Local {
		case "EntitiesDescriptor":
			// descend into the aggregate
		case "EntityDescriptor":
			entity := &saml.EntityDescriptor{}
			if err := decoder.DecodeElement(entity, &start); err != nil {
				return nil, err
			}
			if len(entity.IDPSSODescriptors) > 0 {
				return entity, nil
			}
		default:
			if err := decoder.Skip(); err != nil {
				return nil, err
			}
		}
	}
}

// FetchMetadata returns metadata from an IDP metadata URL.
//
// The metadata names the certificates the service provider trusts to sign
// assertions, so whoever controls the response controls who can log in. It
// is not authenticated beyond what httpClient does: use an https URL, and
// prefer FetchSignedMetadata, or metadata kept with the application.
func FetchMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseMetadata(data)
}

// FetchMetadataByEntityID fetches metadata from metadataURL and returns the
// entity whose entityID is entityID. Use it to select an IDP from aggregate
// metadata, such as a federation's metadata feed. See ParseMetadataByEntityID.
func FetchMetadataByEntityID(ctx context.Context, httpClient *http.Client, metadataURL url.URL, entityID string) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseMetadataByEntityID(data, entityID)
}

// FetchSignedMetadata fetches metadata from metadataURL and parses it with
// ParseSignedMetadata: its root element must carry a valid signature made
// with one of certs.
func FetchSignedMetadata(ctx context.Context, httpClient *http.Client, metadataURL url.URL, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseSignedMetadata(data, certs)
}

// FetchSignedMetadataByEntityID fetches metadata from metadataURL and parses
// it with ParseSignedMetadataByEntityID.
func FetchSignedMetadataByEntityID(ctx context.Context, httpClient *http.Client, metadataURL url.URL, entityID string, certs []*x509.Certificate) (*saml.EntityDescriptor, error) {
	data, err := fetchMetadataBytes(ctx, httpClient, metadataURL)
	if err != nil {
		return nil, err
	}
	return ParseSignedMetadataByEntityID(data, entityID, certs)
}

// MaxMetadataSize is the size in bytes of the largest metadata document that
// FetchMetadata and the other Fetch functions read. A larger response is
// refused rather than read into memory in full. The default leaves room for
// federation aggregates, which run to tens of megabytes; lower it when
// fetching a single IDP's metadata.
var MaxMetadataSize int64 = 256 << 20

func fetchMetadataBytes(ctx context.Context, httpClient *http.Client, metadataURL url.URL) ([]byte, error) {
	req, err := http.NewRequest("GET", metadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	req = req.WithContext(ctx)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := resp.Body.Close(); err != nil {
			logger.DefaultLogger.Printf("Error while closing response body during fetch metadata: %v", err)
		}
	}()
	if resp.StatusCode >= 400 {
		return nil, fmt.Errorf("failed to fetch metadata: unexpected status code %d", resp.StatusCode)
	}

	limit := MaxMetadataSize
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("failed to fetch metadata: response is larger than %d bytes (MaxMetadataSize)", limit)
	}
	return data, nil
}
