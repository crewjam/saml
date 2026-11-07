package samlsp

import (
	"bytes"
	"context"
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
// IDPSSODescriptor (nested <EntitiesDescriptor> elements included):
// ParseMetadata cannot tell which of several IDPs the caller means to
// trust. Use ParseMetadataByEntityID to pick one out of an aggregate.
func ParseMetadata(data []byte) (*saml.EntityDescriptor, error) {
	entity := &saml.EntityDescriptor{}

	if err := xrv.Validate(bytes.NewBuffer(data)); err != nil {
		return nil, err
	}

	err := xml.Unmarshal(data, entity)

	// this comparison is ugly, but it is how the error is generated in encoding/xml
	if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
		entities := &saml.EntitiesDescriptor{}
		if err := xml.Unmarshal(data, entities); err != nil {
			return nil, err
		}

		if n := countIDPEntities(entities); n > 1 {
			return nil, fmt.Errorf("metadata holds %d entities with an IDPSSODescriptor; use ParseMetadataByEntityID to choose one", n)
		}
		for i, e := range entities.EntityDescriptors {
			if len(e.IDPSSODescriptors) > 0 {
				return &entities.EntityDescriptors[i], nil
			}
		}
		return nil, errors.New("no entity found with IDPSSODescriptor")
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

// FetchMetadata returns metadata from an IDP metadata URL.
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

	return io.ReadAll(resp.Body)
}
