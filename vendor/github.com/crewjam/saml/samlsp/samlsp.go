// Package samlsp provides helpers that can be used to protect web
// services using SAML.
package samlsp

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/logger"
)

// Options represents the parameters for creating a new middleware
type Options struct {
	URL               url.URL
	Key               *rsa.PrivateKey
	Logger            logger.Interface
	Certificate       *x509.Certificate
	AllowIDPInitiated bool
	IDPMetadata       *saml.Metadata
	IDPMetadataURL    *url.URL
}

// New creates a new Middleware
func New(opts Options) (*Middleware, error) {

	metadataURL := opts.URL
	metadataURL.Path = metadataURL.Path + "/saml/metadata"
	acsURL := opts.URL
	acsURL.Path = acsURL.Path + "/saml/acs"
	logr := opts.Logger
	if logr == nil {
		logr = logger.DefaultLogger
	}

	m := &Middleware{
		ServiceProvider: saml.ServiceProvider{
			Key:         opts.Key,
			Logger:      logr,
			Certificate: opts.Certificate,
			MetadataURL: metadataURL,
			AcsURL:      acsURL,
			IDPMetadata: opts.IDPMetadata,
		},
		AllowIDPInitiated: opts.AllowIDPInitiated,
		CookieName:        defaultCookieName,
		CookieMaxAge:      defaultCookieMaxAge,
	}

	// fetch the IDP metadata if needed.
	if opts.IDPMetadataURL == nil {
		return m, nil
	}

	c := http.DefaultClient
	req, err := http.NewRequest("GET", opts.IDPMetadataURL.String(), nil)
	if err != nil {
		return nil, err
	}
	// Some providers (like OneLogin) do not work properly unless the User-Agent header is specified.
	// Setting the user agent prevents the 403 Forbidden errors.
	req.Header.Set("User-Agent", "Golang; github.com/crewjam/saml")

	for i := 0; true; i++ {
		resp, err := c.Do(req)
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
			logr.Printf("ERROR: %s: %s (will retry)", opts.IDPMetadataURL, err)
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
