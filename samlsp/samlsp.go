// Package samlsp provides helpers that can be used to protect web
// services using SAML.
package samlsp

import (
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"time"

	"github.com/crewjam/saml"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	URL               string
	Key               string
	Certificate       string
	AllowIDPInitiated bool
	IDPMetadata       *saml.Metadata
	IDPMetadataURL    string
}

// New creates a new Middleware
func New(opts Options) (*Middleware, error) {
	m := &Middleware{
		ServiceProvider: saml.ServiceProvider{
			Key:         opts.Key,
			Certificate: opts.Certificate,
			MetadataURL: opts.URL + "/saml/metadata",
			AcsURL:      opts.URL + "/saml/acs",
			IDPMetadata: opts.IDPMetadata,
		},
		AllowIDPInitiated: opts.AllowIDPInitiated,
	}

	// fetch the IDP metadata if needed.
	if opts.IDPMetadataURL == "" {
		return m, nil
	}

	for i := 0; true; i++ {
		resp, err := http.Get(opts.IDPMetadataURL)
		if err == nil && resp.StatusCode != http.StatusOK {
			err = fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
		}
		var data []byte
		if err == nil {
			data, err = ioutil.ReadAll(resp.Body)
			resp.Body.Close()
		}
		if err != nil {
			if i > 10 {
				return nil, err
			}
			log.Printf("ERROR: %s: %s (will retry)", opts.IDPMetadataURL, err)
			time.Sleep(5 * time.Second)
			continue
		}

		entity := &saml.Metadata{}

		err = xml.Unmarshal(data, entity)

		// this comparison is ugly, but it is how the error is generated in encoding/xml
		if err != nil && err.Error() == "expected element type <EntityDescriptor> but have <EntitiesDescriptor>" {
			entities := &saml.EntitiesDescriptor{}
			if err := xml.Unmarshal(data, entities); err != nil {
				return nil, err
			}

			err = fmt.Errorf("no entity found with IDPSSODescriptor")
			for _, e := range entities.EntityDescriptor {
				if e.IDPSSODescriptor != nil {
					entity = e
					err = nil
				}
			}
		}
		if err != nil {
			return nil, err
		}

		m.ServiceProvider.IDPMetadata = entity
		return m, nil
	}

	panic("unreachable")
}
