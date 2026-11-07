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

	key                    crypto.Signer
	certificate            *x509.Certificate
	intermediates          []*x509.Certificate
	decryptionKeys         []*rsa.PrivateKey
	signRequests           bool
	nameIDFormat           saml.NameIDFormat
	replayState            saml.AssertionReplayCache
	authnContextComparator func(comparison string, requested []string, got string) bool
	clock                  *dsig.Clock

	spOptions []ServiceProviderOption
}

// New returns a Config for the service provider entityID.
//
// identityProvider supplies the metadata of the IdP that the SP trusts.
// It is called with the context of each method. See RemoteMetadata,
// StaticMetadata and StaticMetadataBytes.
//
// The entity ID is conventionally the URL where the SP serves its metadata
// (see ServeMetadata), such as "https://sp.example.com/saml/metadata". The
// assertion consumer service (ACS), where the IdP sends its Responses, is
// then beside it by default, at "acs": "https://sp.example.com/saml/acs"
// in that example. Serve ParseResponse there, or choose another URL with
// WithACSURL. If the entity ID is not a URL, such as a URN, WithACSURL is
// required.
//
// New returns an error if an argument is missing or a URL is not
// absolute. It does not call identityProvider.
func New(identityProvider MetadataFunc, entityID string, opts ...Option) (*Config, error) {
	if identityProvider == nil {
		return nil, errors.New("samlsp: the identity provider is nil")
	}
	if entityID == "" {
		return nil, errors.New("samlsp: the entity ID is empty")
	}
	c := &Config{identityProvider: identityProvider, entityID: entityID}
	var o configOptions
	for _, opt := range opts {
		if opt != nil {
			opt.applyConfig(c, &o)
		}
	}

	var err error
	if o.acsURL != "" {
		if c.acsURL, err = absoluteURL("ACS URL", o.acsURL); err != nil {
			return nil, err
		}
	} else {
		u, err := url.Parse(entityID)
		if err != nil || !u.IsAbs() || u.Host == "" {
			return nil, fmt.Errorf("samlsp: the entity ID %q is not a URL to put the ACS beside; use WithACSURL", entityID)
		}
		c.acsURL = *u.ResolveReference(&url.URL{Path: "acs"})
	}
	if o.sloURL != "" {
		if c.sloURL, err = absoluteURL("SLO URL", o.sloURL); err != nil {
			return nil, err
		}
	}
	if c.replayState == nil {
		c.replayState = newMemoryReplayState(c.clock.Now)
	}
	if c.signRequests && signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignAuthnRequests needs an RSA or ECDSA key (see WithKey)")
	}
	return c, nil
}

// harden turns on every check that package saml leaves off by default only
// for compatibility. A ServiceProviderOption can turn one off again.
func harden(sp *saml.ServiceProvider) {
	// Check the AuthnContextClassRef against WithAuthnContext.
	sp.ValidateAuthnContextClassRef = true
	// Refuse assertions with conditions that are not understood
	// (saml-core §2.5.1.1).
	sp.RejectUnknownConditions = true
	// Decrypt AES-CBC only inside a signed Response: CBC does not
	// authenticate the ciphertext (saml-core errata E93).
	sp.RequireSignedResponseForCBC = true
	// Refuse signatures made with SHA-1.
	sp.RejectSHA1Signatures = true
	// Refuse messages once the IdP metadata's validUntil has passed.
	sp.RejectExpiredIDPMetadata = true
	// Resolve only type 0x0004 artifacts issued by this IdP.
	sp.RequireStandardArtifacts = true
	// Keep RelayState within 80 bytes (saml-bindings §3.4.3, §3.5.3).
	sp.LimitRelayStateLength = true
}

// absoluteURL parses s, which must be an absolute URL with a host.
func absoluteURL(what, s string) (url.URL, error) {
	u, err := url.Parse(s)
	if err != nil {
		return url.URL{}, fmt.Errorf("samlsp: invalid %s: %w", what, err)
	}
	if !u.IsAbs() || u.Host == "" {
		return url.URL{}, fmt.Errorf("samlsp: the %s must be an absolute URL, not %q", what, s)
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

// WithACSURL sets the absolute URL of the SP's assertion consumer service,
// where the IdP sends its Responses. The handler at this URL calls
// ParseResponse. The default is "acs" beside the entity ID (see New).
func WithACSURL(acsURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.acsURL = acsURL })
}

// WithSLOURL sets the absolute URL of the SP's single logout service. The
// handler at this URL calls ParseLogoutRequest and ParseLogoutResponse.
// Without it, the SP metadata advertises no single logout service.
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

// WithReplayState sets where ParseResponse and ParseLogoutRequest record
// the IDs of the messages they accept, so that each is accepted only once.
//
// By default, a Config records them in memory, which protects one process
// only: a Response replayed to another process, or after a restart, is
// accepted. Applications served by several processes need state that the
// processes share, such as a table with a unique key on the ID. Consume
// must fail with saml.ErrAssertionReplayed for an ID it has recorded with
// an expiry that has not passed, and may forget an ID once its expiry has
// passed. Records need no size limit: see the package documentation.
func WithReplayState(state saml.AssertionReplayCache) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.replayState = state })
}

// WithAuthnContextComparator sets how ParseResponse decides whether the
// authentication context class the IdP used satisfies a WithAuthnContext
// whose comparison is not ComparisonExact. satisfies reports whether got
// is acceptable when classes were requested with comparison. The SAML
// specification leaves the order of the classes to each deployment.
func WithAuthnContextComparator(satisfies func(comparison AuthnContextComparison, requested []AuthnContextClass, got AuthnContextClass) bool) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.authnContextComparator = func(comparison string, requested []string, got string) bool {
			classes := make([]AuthnContextClass, len(requested))
			for i, r := range requested {
				classes[i] = AuthnContextClass(r)
			}
			return satisfies(AuthnContextComparison(comparison), classes, AuthnContextClass(got))
		}
	})
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
		ReplayCache:       c.replayState,
		Clock:             c.clock,

		AuthnContextClassRefComparator: c.authnContextComparator,
	}
	harden(sp)
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
