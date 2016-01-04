package samlsp

import (
	"encoding/xml"
	"fmt"
	"log"
	"net/http"
	"time"

	"github.com/crewjam/saml"
)

type Options struct {
	URL               string
	Key               string
	Certificate       string
	AllowIDPInitiated bool
	IDPMetadata       *saml.Metadata
	IDPMetadataURL    string
}

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

	// fetch the IDP metadata if needed. We do this asyncronously so that
	// we can start service the service provider metadata, which might be required
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

			md := saml.EntitiesDescriptor{}
			if err := xml.NewDecoder(resp.Body).Decode(&md); err != nil {
				return nil, err
			}
			for _, entity := range md.EntityDescriptor {
				if entity.IDPSSODescriptor != nil {
					m.ServiceProvider.IDPMetadata = entity
					break
				}
			}
			break
		}
	}

	return m, nil
}
