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

	key                    crypto.Signer
	certificate            *x509.Certificate
	intermediates          []*x509.Certificate
	decryptionKeys         []*rsa.PrivateKey
	encryptionKey          *rsa.PrivateKey
	encryptionCert         *x509.Certificate
	signRequests           bool
	acceptBaseID           bool
	nameIDFormat           saml.NameIDFormat
	replayState            saml.AssertionReplayCache
	authnContextComparator func(comparison string, requested []string, got string) bool
	clock                  *dsig.Clock
	httpClient             *http.Client
	signatureMethod        string

	spOptions     []ServiceProviderOption
	spMetadata    spMetadataOptions
	checks        []func(*saml.ServiceProvider) error
	metadataHooks []func(*saml.EntityDescriptor)
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
	if c.replayState == nil {
		c.replayState = newMemoryReplayState(c.clock.Now)
	}
	if c.encryptionKey != nil || c.encryptionCert != nil {
		if c.encryptionKey == nil || c.encryptionCert == nil {
			return nil, errors.New("samlsp: WithEncryptionKey needs both the key and its certificate")
		}
		if pub, ok := c.encryptionCert.PublicKey.(*rsa.PublicKey); !ok || !pub.Equal(&c.encryptionKey.PublicKey) {
			return nil, errors.New("samlsp: the certificate of WithEncryptionKey is not for its key")
		}
	}
	if err := c.spMetadata.check(); err != nil {
		return nil, err
	}
	if c.signatureMethod != "" {
		if err := checkSignatureMethod(c.signatureMethod, c.key); err != nil {
			return nil, err
		}
	}
	if sp := c.spForMetadata(nil); sp.SignMetadata && signatureMethod(c.key) == "" {
		return nil, errors.New("samlsp: SignMetadata needs an RSA or ECDSA key (see WithKey)")
	}
	if len(c.checks) > 0 {
		sp := c.spForMetadata(nil)
		for _, check := range c.checks {
			if err := check(sp); err != nil {
				return nil, err
			}
		}
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
}

type optionFunc func(c *Config, o *configOptions)

func (f optionFunc) applyConfig(c *Config, o *configOptions) { f(c, o) }

// WithACSURL sets the absolute URL of the SP's assertion consumer service,
// where the IdP sends its Responses. The handler at this URL calls
// ParseResponse. The default is "acs" beside the entity ID (see New).
func WithACSURL(acsURL string) Option {
	return optionFunc(func(_ *Config, o *configOptions) { o.acsURL = acsURL })
}

// AcceptBaseID makes ParseResponse accept an assertion that identifies the
// user with a saml:BaseID instead of a NameID (saml-core §2.2.3). A
// BaseID's content is defined by its xsi:type, which this package does not
// interpret: it is given as Assertion.BaseID, and NameID is zero. Without
// it, such assertions are refused. (For LogoutRequests, see
// x/samlsp/slo.AcceptBaseID.)
var AcceptBaseID Option = optionFunc(func(c *Config, _ *configOptions) { c.acceptBaseID = true })

// ACSURL returns the URL of the SP's assertion consumer service.
func (c *Config) ACSURL() string { return c.acsURL.String() }

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

// WithEncryptionKey sets an RSA key pair that the IdP encrypts assertions
// to, separate from the signing key of WithKey. cert is advertised in the
// SP metadata for encryption, and key decrypts. Use it when the signing key
// cannot decrypt (it is ECDSA, or held in an HSM that only signs), or to
// rotate the two keys apart.
//
// Without it, the key of WithKey is advertised for encryption too, if it
// is an RSA key.
func WithEncryptionKey(key *rsa.PrivateKey, cert *x509.Certificate) Option {
	return optionFunc(func(c *Config, _ *configOptions) {
		c.encryptionKey, c.encryptionCert = key, cert
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

// WithReplayState sets where ParseResponse (and the LogoutRequests of
// x/samlsp/slo) record the IDs of the messages they accept, so that each is
// accepted only once.
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

// WithSignatureMethod sets the XML signature algorithm of everything the
// SP signs: AuthnRequests (with SignAuthnRequests), logout messages,
// attribute queries and signed metadata. It must suit the key of WithKey:
// dsig.RSASHA256SignatureMethod, RSASHA384 or RSASHA512 for an RSA key,
// and dsig.ECDSASHA256SignatureMethod, ECDSASHA384 or ECDSASHA512 for an
// ECDSA key. SHA-1 is refused. The default is SHA-256.
func WithSignatureMethod(method string) Option {
	return optionFunc(func(c *Config, _ *configOptions) { c.signatureMethod = method })
}

// checkSignatureMethod returns an error if method cannot be used with key.
func checkSignatureMethod(method string, key crypto.Signer) error {
	if signatureMethod(key) == "" {
		return errors.New("samlsp: WithSignatureMethod needs an RSA or ECDSA key (see WithKey)")
	}
	_, isRSA := key.Public().(*rsa.PublicKey)
	switch method {
	case dsig.RSASHA256SignatureMethod, dsig.RSASHA384SignatureMethod, dsig.RSASHA512SignatureMethod:
		if !isRSA {
			return fmt.Errorf("samlsp: signature method %s needs an RSA key", method)
		}
	case dsig.ECDSASHA256SignatureMethod, dsig.ECDSASHA384SignatureMethod, dsig.ECDSASHA512SignatureMethod:
		if isRSA {
			return fmt.Errorf("samlsp: signature method %s needs an ECDSA key", method)
		}
	case dsig.RSASHA1SignatureMethod, dsig.ECDSASHA1SignatureMethod:
		return fmt.Errorf("samlsp: SHA-1 signature method %s is refused", method)
	default:
		return fmt.Errorf("samlsp: unknown signature method %q", method)
	}
	return nil
}

// signWithLogoutMethod makes sp sign SOAP messages, attribute queries and
// metadata with the method of LogoutSignatureMethod, which is the one of
// WithSignatureMethod. Package saml signs those with SignatureMethod,
// which also turns on the signing of AuthnRequests, so it is set only on
// the ServiceProvider of a call that makes none.
func signWithLogoutMethod(sp *saml.ServiceProvider) {
	if sp.LogoutSignatureMethod != "" {
		sp.SignatureMethod = sp.LogoutSignatureMethod
	}
}

// WithClock sets the time source used to check validity periods. It is
// mainly useful in tests.
func WithClock(clock *dsig.Clock) ClockOption { return ClockOption{clock} }

// ClockOption is the option that WithClock returns. It is both an Option,
// for New, and a MetadataOption, for RemoteMetadata and MDQMetadata, whose
// refresh times it judges.
type ClockOption struct{ clock *dsig.Clock }

func (o ClockOption) applyConfig(c *Config, _ *configOptions) { c.clock = o.clock }

func (o ClockOption) applyMetadata(m *metadataOptions) { m.clock = o.clock }

// EntityID returns the entityID of the service provider.
func (c *Config) EntityID() string { return c.entityID }

// ServiceProviderOption customizes the saml.ServiceProvider that a Config
// method builds and uses, for settings that have no Option of their own.
// Pass it to New to apply it to every call, or to a single method: it is
// an Option, a MessageOption and a ResponseOption. The
// options of a call are applied after those passed to New.
type ServiceProviderOption func(sp *saml.ServiceProvider)

func (f ServiceProviderOption) applyConfig(c *Config, _ *configOptions) {
	c.spOptions = append(c.spOptions, f)
}
func (f ServiceProviderOption) applyAuthn(o *authnOptions)       { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyMessage(o *messageOptions)   { o.sp = append(o.sp, f) }
func (f ServiceProviderOption) applyResponse(o *responseOptions) { o.sp = append(o.sp, f) }

// WithServiceProvider returns a ServiceProviderOption that calls fn.
func WithServiceProvider(fn func(sp *saml.ServiceProvider)) ServiceProviderOption {
	return ServiceProviderOption(fn)
}

// SignMetadata makes ServeMetadata and MetadataXML sign the SP metadata
// with the key of WithKey. Pass it to New. Metadata returns the metadata
// as a struct, which carries no signature.
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
	sp := c.localServiceProvider()
	sp.IDPMetadata = idpMetadata
	c.applyServiceProviderOptions(sp, opts)
	return sp, nil
}

// localServiceProvider returns a new saml.ServiceProvider configured from
// c, without the identity provider's metadata and without applying any
// ServiceProviderOption.
func (c *Config) localServiceProvider() *saml.ServiceProvider {
	sp := &saml.ServiceProvider{
		EntityID:              c.entityID,
		Key:                   c.key,
		Certificate:           c.certificate,
		Intermediates:         c.intermediates,
		DecryptionKeys:        c.decryptionKeys,
		EncryptionKey:         c.encryptionKey,
		EncryptionCertificate: c.encryptionCert,
		HTTPClient:            c.httpClient,
		AcsURL:                c.acsURL,
		AuthnNameIDFormat:     c.nameIDFormat,
		ReplayCache:           c.replayState,
		Clock:                 c.clock,

		AuthnContextClassRefComparator: c.authnContextComparator,
		AcceptAssertionBaseID:          c.acceptBaseID,
	}
	harden(sp)
	method := c.signatureMethod
	if method == "" {
		method = signatureMethod(c.key)
	}
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
// MetadataFunc. It is not signed, whatever SignMetadata says: for the
// signed document, use MetadataXML.
func (c *Config) Metadata(_ context.Context, opts ...ServiceProviderOption) *saml.EntityDescriptor {
	md := c.spForMetadata(opts).Metadata()
	c.decorateMetadata(md)
	return md
}

// spForMetadata returns the saml.ServiceProvider that describes this SP's
// metadata. The SP metadata does not depend on the IdP, so it is served
// even when the IdP metadata cannot be had.
func (c *Config) spForMetadata(opts []ServiceProviderOption) *saml.ServiceProvider {
	sp := c.localServiceProvider()
	c.applyServiceProviderOptions(sp, opts)
	return sp
}

// ServeMetadata is an http.HandlerFunc that serves this service provider's
// metadata, conventionally at the entity ID's URL. If New was passed
// SignMetadata, the metadata is signed.
func (c *Config) ServeMetadata(w http.ResponseWriter, r *http.Request) {
	buf, err := c.MetadataXML(r.Context())
	if err != nil {
		http.Error(w, http.StatusText(http.StatusInternalServerError), http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/samlmetadata+xml")
	_, _ = w.Write(buf) //nolint:gosec // our own metadata, served as application/samlmetadata+xml
}

// decorateMetadata adds to md, the SP metadata, what the options add.
func (c *Config) decorateMetadata(md *saml.EntityDescriptor) {
	c.spMetadata.apply(md)
	for _, modify := range c.metadataHooks {
		modify(md)
	}
}

// MetadataXML returns the metadata of this service provider as the XML
// document that ServeMetadata serves: signed if SignMetadata was passed to
// New or is in opts. Like Metadata, it applies opts after the
// ServiceProviderOptions passed to New, and does not call the identity
// provider's MetadataFunc.
func (c *Config) MetadataXML(_ context.Context, opts ...ServiceProviderOption) ([]byte, error) {
	sp := c.spForMetadata(opts)
	md := sp.Metadata()
	c.decorateMetadata(md)
	if !sp.SignMetadata {
		return xml.MarshalIndent(md, "", "  ")
	}
	signWithLogoutMethod(sp)
	el, err := sp.SignEntityDescriptor(md)
	if err != nil {
		return nil, err
	}
	doc := etree.NewDocument()
	doc.SetRoot(el)
	return doc.WriteToBytes()
}
