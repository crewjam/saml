// Package samlsp provides helpers that can be used to protect web
// services using SAML.
package samlsp

import (
	"encoding/xml"
	"fmt"
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
	if opts.IDPMetadataURL != "" {
		for i := 0; true; i++ {
			resp, err := http.Get(opts.IDPMetadataURL)
			if err == nil && resp.StatusCode != http.StatusOK {
				err = fmt.Errorf("%d %s", resp.StatusCode, resp.Status)
			}
			if err != nil {
				if i > 10 {
					return nil, err
				}
				log.Printf("ERROR: %s: %s (will retry)", opts.IDPMetadataURL, err)
				time.Sleep(5 * time.Second)
				continue
			}

			m.ServiceProvider.IDPMetadata = &saml.Metadata{}
			if err := xml.NewDecoder(resp.Body).Decode(m.ServiceProvider.IDPMetadata); err != nil {
				return nil, err
			}
			break
		}
	}

	return m, nil
}
