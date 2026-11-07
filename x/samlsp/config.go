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

// Config is a SAML service provider (SP) and the identity provider (IdP)
// it trusts. Create one with New. A Config is immutable and safe for
// concurrent use.
type Config struct {
	identityProvider MetadataFunc
	entityID         string
	acsURL           url.URL
	sloURL           url.URL

	key            crypto.Signer
	certificate    *x509.Certificate
	intermediates  []*x509.Certificate
	decryptionKeys []*rsa.PrivateKey
	signRequests   bool
	nameIDFormat   saml.NameIDFormat
	replayCache    saml.AssertionReplayCache
	clock          *dsig.Clock

	spOptions []ServiceProviderOption
}

// New returns a Config for the service provider entityID.
//
// identityProvider supplies the metadata of the IdP that the SP trusts.
// It is called with the context of each method. See RemoteMetadata,
// ParseMetadata and StaticMetadata.
//
// The entity ID is conventionally the URL where the SP serves its metadata
// (see ServeMetadata), such as "https://sp.example.com/saml/metadata". The
// SP's other URLs are resolved against it as URL references. The assertion
// consumer service (ACS), where the IdP sends its Responses, is at "acs" by
// default: "https://sp.example.com/saml/acs" in that example. Serve
// ParseResponse there, or choose another URL with WithACSURL. If the entity
// ID is not an absolute URL, such as a URN, WithACSURL must give an
// absolute one.
//
// New returns an error if an argument is missing or a URL cannot be
// resolved. It does not call identityProvider.
func New(identityProvider MetadataFunc, entityID string, opts ...Option) (*Config, error) {
	if identityProvider == nil {
		return nil, errors.New("samlsp: the identity provider is nil")
	}
	if entityID == "" {
		return nil, errors.New("samlsp: the entity ID is empty")
	}
	c := &Config{identityProvider: identityProvider, entityID: entityID}
	o := configOptions{acsURL: "acs"}
	for _, opt := range opts {
		if opt != nil {
			opt.applyConfig(c, &o)
		}
	}

	var base *url.URL
	if u, err := url.Parse(entityID); err == nil && u.IsAbs() && u.Host != "" {
		base = u
	}
	var err error
	if c.acsURL, err = resolveURL(base, "ACS URL", o.acsURL); err != nil {
		return nil, err
	}
	if o.sloURL != "" {
		if c.sloURL, err = resolveURL(base, "SLO URL", o.sloURL); err != nil {
			return nil, err
		}
	}
	if c.signRequests && signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignAuthnRequests needs an RSA or ECDSA key (see WithKey)")
	}
	return c, nil
}

// resolveURL returns ref resolved against base, the entity ID as a URL, or
// nil if the entity ID is not one. The result must be absolute.
func resolveURL(base *url.URL, what, ref string) (url.URL, error) {
	if ref == "" {
		return url.URL{}, fmt.Errorf("samlsp: the %s is empty", what)
	}
	u, err := url.Parse(ref)
	if err != nil {
		return url.URL{}, fmt.Errorf("samlsp: invalid %s: %w", what, err)
	}
	if !u.IsAbs() {
		if base == nil {
			return url.URL{}, fmt.Errorf("samlsp: the %s %q is relative, and the entity ID is not a URL to resolve it against", what, ref)
		}
		u = base.ResolveReference(u)
	}
	if u.Host == "" {
		return url.URL{}, fmt.Errorf("samlsp: the %s %q has no host", what, u)
	}
	return *u, nil
}

// Option configures New.
type Option interface {
	applyConfig(c *Config, o *configOptions)
}

// configOptions holds options that New validates after applying them.
type configOptions struct {
	acsURL string
	sloURL string
}

type optionFunc func(c *Config, o *configOptions)

func (f optionFunc) applyConfig(c *Config, o *configOptions) { f(c, o) }

// WithACSURL sets the URL of the SP's assertion consumer service, where the
// IdP sends its Responses. The handler at this URL calls ParseResponse. A
// relative URL is resolved against the entity ID. The default is "acs".
func WithACSURL(acsURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.acsURL = acsURL })
}

// WithSLOURL sets the URL of the SP's single logout service. The handler at
// this URL calls ParseLogoutRequest and ParseLogoutResponse. A relative URL
// is resolved against the entity ID: WithSLOURL("slo") puts it beside the
// ACS. Without it, the SP metadata advertises no single logout service.
func WithSLOURL(sloURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.sloURL = sloURL })
}

// ACSURL returns the URL of the SP's assertion consumer service.
func (c *Config) ACSURL() string { return c.acsURL.String() }

// SLOURL returns the URL of the SP's single logout service, or "" if there
// is none.
func (c *Config) SLOURL() string { return c.sloURL.String() }

// WithKey sets the SP's private key and its certificate, which is published
// in the SP metadata, with any intermediates of its chain. The key always
// signs logout messages, and it signs AuthnRequests with
// SignAuthnRequests. If it is an *rsa.PrivateKey, it also decrypts
// encrypted assertions.
func WithKey(key crypto.Signer, cert *x509.Certificate, intermediates ...*x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.key, c.certificate = key, cert
		c.intermediates = append([]*x509.Certificate(nil), intermediates...)
	})
}

// WithDecryptionKeys adds keys that can decrypt encrypted assertions, for
// key rotation.
func WithDecryptionKeys(keys ...*rsa.PrivateKey) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.decryptionKeys = append(c.decryptionKeys, keys...)
	})
}

// SignAuthnRequests makes AuthnRequests carry a signature by the key of
// WithKey, using RSA-SHA256 or ECDSA-SHA256.
var SignAuthnRequests Option = optionFunc(func(c *Config, _ *configOptions) { c.signRequests = true })

// WithNameIDFormat sets the NameID format requested from the IdP. The
// default is transient.
func WithNameIDFormat(format saml.NameIDFormat) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.nameIDFormat = format })
}

// WithReplayCache makes ParseResponse refuse an assertion that cache has
// already seen. Applications served by several processes need a cache
// that the processes share.
func WithReplayCache(cache saml.AssertionReplayCache) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.replayCache = cache })
}

// WithClock sets the time source used to check validity periods. It is
// mainly useful in tests.
func WithClock(clock *dsig.Clock) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.clock = clock })
}

// EntityID returns the entityID of the service provider.
func (c *Config) EntityID() string { return c.entityID }

// ServiceProviderOption customizes the saml.ServiceProvider that a Config
// method builds and uses, for settings that have no Option of their own.
// Pass it to New to apply it to every call, or to a single method: it is
// an Option, an AuthnOption, a ResponseOption and a LogoutOption. The
// options of a call are applied after those passed to New.
type ServiceProviderOption func(sp *saml.ServiceProvider)

func (f ServiceProviderOption) applyConfig(c *Config, _ *configOptions) {
	c.spOptions = append(c.spOptions, f)
}
func (f ServiceProviderOption) applyAuthn(o *authnOptions)       { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyLogout(o *logoutOptions)     { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyResponse(o *responseOptions) { o.sp = append(o.sp, f) }

// WithServiceProvider returns a ServiceProviderOption that calls fn.
func WithServiceProvider(fn func(sp *saml.ServiceProvider)) ServiceProviderOption {
	return ServiceProviderOption(fn)
}

// SignMetadata makes ServeMetadata and Metadata sign the SP metadata with
// the key of WithKey. Pass it to New.
var SignMetadata ServiceProviderOption = func(sp *saml.ServiceProvider) { sp.SignMetadata = true }

// RejectUnknownConditions makes ParseResponse refuse an assertion whose
// Conditions hold a condition this package does not understand, as
// saml-core §2.5.1.1 requires.
var RejectUnknownConditions ServiceProviderOption = func(sp *saml.ServiceProvider) { sp.RejectUnknownConditions = true }

// applyServiceProviderOptions applies the options of c, then extra, to sp.
func (c *Config) applyServiceProviderOptions(sp *saml.ServiceProvider, extra []ServiceProviderOption) {
	for _, opt := range c.spOptions {
		if opt != nil {
			opt(sp)
		}
	}
	for _, opt := range extra {
		if opt != nil {
			opt(sp)
		}
	}
}

// serviceProvider returns a new saml.ServiceProvider configured from c,
// with the identity provider's metadata, and with the
// ServiceProviderOptions passed to New and then opts applied.
func (c *Config) serviceProvider(ctx context.Context, opts []ServiceProviderOption) (*saml.ServiceProvider, error) {
	idpMetadata, err := c.identityProvider(ctx)
	if err != nil {
		return nil, fmt.Errorf("samlsp: cannot get identity provider metadata: %w", err)
	}
	if err := checkIDPMetadata(idpMetadata); err != nil {
		return nil, err
	}
	sp := c.localServiceProvider(ctx)
	sp.IDPMetadata = idpMetadata
	c.applyServiceProviderOptions(sp, opts)
	return sp, nil
}

// localServiceProvider returns a new saml.ServiceProvider configured from
// c, without the identity provider's metadata and without applying any
// ServiceProviderOption.
func (c *Config) localServiceProvider(ctx context.Context) *saml.ServiceProvider {
	sp := &saml.ServiceProvider{
		EntityID:          c.entityID,
		Key:               c.key,
		Certificate:       c.certificate,
		Intermediates:     c.intermediates,
		DecryptionKeys:    c.decryptionKeys,
		HTTPClient:        clientFromContext(ctx),
		AcsURL:            c.acsURL,
		SloURL:            c.sloURL,
		AuthnNameIDFormat: c.nameIDFormat,
		ReplayCache:       c.replayCache,
		Clock:             c.clock,
	}
	if c.sloURL.String() != "" {
		sp.LogoutBindings = []string{saml.HTTPRedirectBinding, saml.HTTPPostBinding}
	}
	method := signatureMethod(c.key)
	if c.signRequests {
		sp.SignatureMethod = method
	}
	// The single logout profile requires logout messages to be signed with
	// the HTTP-Redirect and HTTP-POST bindings (saml-profiles §4.4.3), so
	// sign them whenever there is a key that can.
	sp.LogoutSignatureMethod = method
	return sp
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
// with the identity provider. It does not call the identity provider's
// MetadataFunc.
func (c *Config) Metadata(ctx context.Context, opts ...ServiceProviderOption) *saml.EntityDescriptor {
	return c.spForMetadata(ctx, opts).Metadata()
}

// spForMetadata returns the saml.ServiceProvider that describes this SP's
// metadata. The SP metadata does not depend on the IdP, so it is served
// even when the IdP metadata cannot be had.
func (c *Config) spForMetadata(ctx context.Context, opts []ServiceProviderOption) *saml.ServiceProvider {
	sp := c.localServiceProvider(ctx)
	c.applyServiceProviderOptions(sp, opts)
	return sp
}

// ServeMetadata is an http.HandlerFunc that serves this service provider's
// metadata, conventionally at the entity ID's URL. If New was passed
// SignMetadata, the metadata is signed.
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
	sp := c.spForMetadata(ctx, nil)
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
