package samlsp

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"

	"github.com/beevik/etree"
	dsig "github.com/russellhaering/goxmldsig"

	"github.com/crewjam/saml"
	"github.com/crewjam/saml/internal/signerutil"
)

// Config describes a SAML service provider and the identity provider it
// trusts. It is plain data: fill in the fields and call its methods. A Config must not be
// modified while it is in use, and it is safe for concurrent use.
type Config struct {
	// IdentityProvider is the identity provider that this SP trusts. It is required.
	IdentityProvider *IdentityProvider

	// EntityID is the entityID of this service provider. If empty,
	// MetadataURL is used.
	EntityID string

	// ACSURL is the absolute URL of this SP's assertion consumer service,
	// where the IdP sends responses. The handler at this URL calls
	// ParseResponse. It is required.
	ACSURL string

	// MetadataURL is the absolute URL where this SP serves its metadata
	// (see ServeMetadata). It is required if EntityID is empty.
	MetadataURL string

	// SLOURL is the absolute URL of this SP's single logout service. The
	// handler at this URL calls ParseLogoutRequest and ParseLogoutResponse.
	// If it is empty, the SP metadata advertises no single logout service.
	SLOURL string

	// Key is the SP's private key. It signs requests when SignRequests is
	// set, and it always signs logout messages. If it is an *rsa.PrivateKey,
	// it also decrypts encrypted assertions. Certificate is its certificate,
	// which is published in the SP metadata.
	Key         crypto.Signer
	Certificate *x509.Certificate

	// Intermediates are further certificates of Certificate's chain to
	// publish in the metadata.
	Intermediates []*x509.Certificate

	// DecryptionKeys are other keys that can decrypt encrypted assertions,
	// for key rotation.
	DecryptionKeys []*rsa.PrivateKey

	// SignRequests makes AuthnRequests carry a signature by Key, using
	// RSA-SHA256 or ECDSA-SHA256.
	SignRequests bool

	// NameIDFormat is the NameID format requested from the IdP. If it is
	// empty, transient is requested.
	NameIDFormat saml.NameIDFormat

	// ReplayCache, if set, makes ParseResponse refuse an assertion it has already
	// accepted. Applications served by several processes need a cache
	// that the processes share.
	ReplayCache saml.AssertionReplayCache

	// Clock, if set, is the time source used to check validity periods.
	// It is mainly useful in tests.
	Clock *dsig.Clock

	// Customize, if set, is called with the saml.ServiceProvider that each
	// method builds from this Config, just before the method uses it. Use
	// it to reach settings that Config does not expose, such as
	// saml.ServiceProvider.RejectUnknownConditions or SignMetadata.
	Customize func(sp *saml.ServiceProvider)
}

// serviceProvider returns a new saml.ServiceProvider configured from c.
func (c *Config) serviceProvider(ctx context.Context) (*saml.ServiceProvider, error) {
	if c.IdentityProvider == nil {
		return nil, errors.New("samlsp: Config.IdentityProvider is nil")
	}
	acsURL, err := absoluteURL("ACSURL", c.ACSURL, true)
	if err != nil {
		return nil, err
	}
	metadataURL, err := absoluteURL("MetadataURL", c.MetadataURL, c.EntityID == "")
	if err != nil {
		return nil, err
	}
	sloURL, err := absoluteURL("SLOURL", c.SLOURL, false)
	if err != nil {
		return nil, err
	}

	sp := &saml.ServiceProvider{
		EntityID:          c.EntityID,
		Key:               c.Key,
		Certificate:       c.Certificate,
		Intermediates:     c.Intermediates,
		DecryptionKeys:    c.DecryptionKeys,
		HTTPClient:        clientFromContext(ctx),
		MetadataURL:       metadataURL,
		AcsURL:            acsURL,
		SloURL:            sloURL,
		IDPMetadata:       c.IdentityProvider.metadata,
		AuthnNameIDFormat: c.NameIDFormat,
		ReplayCache:       c.ReplayCache,
		Clock:             c.Clock,
	}
	if c.SLOURL != "" {
		sp.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
	}

	method := signatureMethod(c.Key)
	if c.SignRequests {
		if method == "" {
			return nil, errors.New("samlsp: SignRequests needs an RSA or ECDSA Key")
		}
		sp.SignatureMethod = method
	}
	// The single logout profile requires logout messages to be signed with
	// the HTTP-Redirect and HTTP-POST bindings (saml-profiles §4.4.3), so
	// sign them whenever there is a key that can.
	sp.LogoutSignatureMethod = method

	if c.Customize != nil {
		c.Customize(sp)
	}
	return sp, nil
}

func absoluteURL(field, s string, required bool) (url.URL, error) {
	if s == "" {
		if required {
			return url.URL{}, fmt.Errorf("samlsp: Config.%s is required", field)
		}
		return url.URL{}, nil
	}
	u, err := url.Parse(s)
	if err != nil {
		return url.URL{}, fmt.Errorf("samlsp: invalid Config.%s: %w", field, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return url.URL{}, fmt.Errorf("samlsp: Config.%s must be an absolute URL, not %q", field, s)
	}
	return *u, nil
}

// signatureMethod returns the XML signature method for key, or "" if key is
// nil or cannot make XML signatures.
func signatureMethod(key crypto.Signer) string {
	if signerutil.IsNil(key) {
		return ""
	}
	switch key.Public().(type) {
	case *rsa.PublicKey:
		return dsig.RSASHA256SignatureMethod
	case *ecdsa.PublicKey:
		return dsig.ECDSASHA256SignatureMethod
	default:
		return ""
	}
}

// Metadata returns the metadata of this service provider, to register it
// with the identity provider.
func (c *Config) Metadata() (*saml.EntityDescriptor, error) {
	sp, err := c.serviceProvider(context.Background())
	if err != nil {
		return nil, err
	}
	return sp.Metadata(), nil
}

// ServeMetadata is an http.HandlerFunc that serves this service provider's
// metadata. Serve it at MetadataURL. If Customize sets SignMetadata, the
// metadata is signed with Key.
func (c *Config) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	buf, err := c.metadataBytes(r.Context())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(buf) //nolint:gosec // our own metadata, served as application/samlmetadata+xml
}

func (c *Config) metadataBytes(ctx context.Context) ([]byte, error) {
	sp, err := c.serviceProvider(ctx)
	if err != nil {
		return nil, err
	}
	if !sp.SignMetadata {
		return xml.MarshalIndent(sp.Metadata(), "", "  ")
	}
	el, err := sp.SignedMetadata()
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}
